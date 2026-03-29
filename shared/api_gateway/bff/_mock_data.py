"""
Mock data for BFF views — used as fallback when engines are unavailable.

Each function returns the complete BFF response for one page view,
matching the exact contract the UI expects.
"""

from datetime import datetime, timedelta
import hashlib
import random

# Seed for deterministic data
random.seed(42)

# ── Shared constants ─────────────────────────────────────────────────────────

ACCOUNTS = [
    {"account_id": "588989875114", "account_name": "prod-account", "provider": "aws"},
    {"account_id": "312456789012", "account_name": "staging-account", "provider": "aws"},
    {"account_id": "198765432109", "account_name": "dev-account", "provider": "aws"},
]

REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-south-1"]

AWS_SERVICES = ["ec2", "s3", "rds", "lambda", "iam", "cloudtrail", "kms", "ecs", "eks", "dynamodb", "sqs", "sns", "elasticache", "redshift", "secretsmanager"]

SEVERITIES = ["critical", "high", "medium", "low"]

MITRE_TECHNIQUES = [
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    {"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence"},
    {"id": "T1136", "name": "Create Account", "tactic": "Persistence"},
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
    {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
    {"id": "T1580", "name": "Cloud Infrastructure Discovery", "tactic": "Discovery"},
    {"id": "T1537", "name": "Transfer Data to Cloud Account", "tactic": "Exfiltration"},
    {"id": "T1530", "name": "Data from Cloud Storage", "tactic": "Collection"},
    {"id": "T1485", "name": "Data Destruction", "tactic": "Impact"},
    {"id": "T1496", "name": "Resource Hijacking", "tactic": "Impact"},
]

THREAT_CATEGORIES = ["data_exposure", "privilege_escalation", "lateral_movement", "credential_theft", "resource_hijacking", "persistence", "defense_evasion"]

now = datetime.utcnow()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_finding_id(rule_id: str, resource_uid: str, account: str, region: str) -> str:
    """Deterministic finding_id from composite key."""
    raw = f"{rule_id}|{resource_uid}|{account}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _random_arn(service: str, account: str, region: str, resource_name: str) -> str:
    """Generate a realistic-looking AWS ARN."""
    if service == "s3":
        return f"arn:aws:s3:::{resource_name}"
    if service == "iam":
        return f"arn:aws:iam::{account}:{resource_name}"
    return f"arn:aws:{service}:{region}:{account}:{resource_name}"


def _severity_weight() -> str:
    """Realistic severity distribution: 8% critical, 20% high, 45% medium, 27% low."""
    r = random.random()
    if r < 0.08:
        return "critical"
    if r < 0.28:
        return "high"
    if r < 0.73:
        return "medium"
    return "low"


def _risk_score_for_severity(sev: str) -> int:
    base = {"critical": 90, "high": 72, "medium": 48, "low": 22}
    return base.get(sev, 50) + random.randint(-8, 8)


def _past_date(max_days: int = 30) -> str:
    delta = timedelta(days=random.randint(0, max_days), hours=random.randint(0, 23))
    return (now - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── 1. Threats ───────────────────────────────────────────────────────────────

_THREAT_TITLES = [
    ("Publicly accessible RDS instance with no encryption", "rds", "data_exposure"),
    ("S3 bucket without server-side encryption enabled", "s3", "data_exposure"),
    ("IAM user with console access and no MFA", "iam", "credential_theft"),
    ("Root account used for API calls", "iam", "privilege_escalation"),
    ("Security group allows unrestricted SSH ingress (0.0.0.0/0:22)", "ec2", "lateral_movement"),
    ("Lambda function with admin privileges", "lambda", "privilege_escalation"),
    ("CloudTrail logging disabled in region", "cloudtrail", "defense_evasion"),
    ("KMS key scheduled for deletion", "kms", "data_exposure"),
    ("ECS task definition with host network mode", "ecs", "lateral_movement"),
    ("EKS cluster endpoint publicly accessible", "eks", "lateral_movement"),
    ("DynamoDB table without point-in-time recovery", "dynamodb", "data_exposure"),
    ("SQS queue policy allows cross-account access", "sqs", "lateral_movement"),
    ("SNS topic with open subscription policy", "sns", "data_exposure"),
    ("ElastiCache cluster without encryption at rest", "elasticache", "data_exposure"),
    ("Redshift cluster not encrypted", "redshift", "data_exposure"),
    ("S3 bucket with public ACL", "s3", "data_exposure"),
    ("IAM policy allows full admin access (*:*)", "iam", "privilege_escalation"),
    ("EC2 instance with IMDSv1 enabled", "ec2", "credential_theft"),
    ("RDS instance publicly accessible", "rds", "data_exposure"),
    ("Secrets Manager secret not rotated in 90+ days", "secretsmanager", "credential_theft"),
    ("Security group allows unrestricted RDP ingress", "ec2", "lateral_movement"),
    ("Lambda function with environment variable secrets", "lambda", "credential_theft"),
    ("CloudTrail not delivering logs to S3", "cloudtrail", "defense_evasion"),
    ("IAM role with trust policy allowing any AWS account", "iam", "lateral_movement"),
    ("EC2 instance without detailed monitoring", "ec2", "defense_evasion"),
    ("S3 bucket without versioning enabled", "s3", "data_exposure"),
    ("RDS instance without automated backups", "rds", "data_exposure"),
    ("KMS key with overly permissive key policy", "kms", "privilege_escalation"),
    ("EKS cluster without audit logging", "eks", "defense_evasion"),
    ("IAM access key older than 90 days", "iam", "credential_theft"),
    ("EC2 instance in public subnet with public IP", "ec2", "lateral_movement"),
    ("S3 bucket without lifecycle policy", "s3", "data_exposure"),
    ("DynamoDB table without encryption at rest", "dynamodb", "data_exposure"),
    ("Lambda function runtime approaching end of life", "lambda", "persistence"),
    ("ECS service without network configuration", "ecs", "lateral_movement"),
    ("RDS instance with default master username", "rds", "credential_theft"),
    ("SQS queue without server-side encryption", "sqs", "data_exposure"),
    ("SNS topic without encryption", "sns", "data_exposure"),
    ("IAM user with multiple active access keys", "iam", "credential_theft"),
    ("Redshift cluster publicly accessible", "redshift", "data_exposure"),
]

_ASSIGNEES = ["alice@example.com", "bob@example.com", "carol@example.com", "david@example.com", None]

_REMEDIATION_MAP = {
    "s3": [
        "Enable server-side encryption (SSE-S3 or SSE-KMS) on the bucket",
        "Apply a bucket policy denying unencrypted object uploads",
        "Enable S3 Block Public Access at the account level",
    ],
    "iam": [
        "Enable MFA for all IAM users with console access",
        "Apply least-privilege policies and remove unused permissions",
        "Rotate access keys every 90 days and delete unused keys",
    ],
    "ec2": [
        "Restrict security group ingress to known CIDR ranges",
        "Enable IMDSv2 and disable IMDSv1 on all instances",
        "Move instances to private subnets with NAT gateway",
    ],
    "rds": [
        "Enable encryption at rest using AWS-managed or customer-managed KMS keys",
        "Disable public accessibility and use VPC security groups",
        "Enable automated backups with adequate retention period",
    ],
    "lambda": [
        "Apply least-privilege execution role policies",
        "Store secrets in Secrets Manager, not environment variables",
        "Update runtime to a supported version",
    ],
    "cloudtrail": [
        "Enable CloudTrail in all regions with log file validation",
        "Configure CloudTrail to deliver logs to a centralized S3 bucket",
        "Enable CloudWatch Logs integration for real-time alerting",
    ],
}


def mock_threats() -> dict:
    """Mock response for /api/v1/views/threats."""
    random.seed(42)

    threats = []
    for i in range(40):
        title, service, category = _THREAT_TITLES[i % len(_THREAT_TITLES)]
        acct = random.choice(ACCOUNTS)
        region = random.choice(REGIONS)
        sev = _severity_weight()
        risk = _risk_score_for_severity(sev)
        mitre = random.choice(MITRE_TECHNIQUES)
        resource_name = f"{service}-{random.randint(1000, 9999)}"
        resource_uid = _random_arn(service, acct["account_id"], region, resource_name)
        detection_id = _make_finding_id(f"aws.{service}.{i}", resource_uid, acct["account_id"], region)
        detected = _past_date(60)

        status_choices = ["active"] * 6 + ["investigating"] * 3 + ["resolved"] * 1
        assignee = random.choice(_ASSIGNEES) if random.random() < 0.3 else None

        threats.append({
            "detection_id": detection_id,
            "title": title,
            "severity": sev,
            "risk_score": risk,
            "provider": "AWS",
            "account": acct["account_id"],
            "account_name": acct["account_name"],
            "region": region,
            "resource_uid": resource_uid,
            "resourceType": service,
            "mitreTechnique": mitre["id"],
            "mitreTactic": mitre["tactic"],
            "threat_category": category,
            "status": random.choice(status_choices),
            "detected": detected,
            "lastSeen": _past_date(5),
            "finding_count": random.randint(1, 12),
            "hasAttackPath": random.random() < 0.20,
            "isInternetExposed": random.random() < 0.15,
            "remediationSteps": _REMEDIATION_MAP.get(service, [
                "Review the resource configuration against CIS benchmarks",
                "Apply the recommended security controls",
                "Monitor for recurrence after remediation",
            ]),
            "assignee": assignee,
        })

    # Severity counts
    critical = sum(1 for t in threats if t["severity"] == "critical")
    high = sum(1 for t in threats if t["severity"] == "high")
    medium = sum(1 for t in threats if t["severity"] == "medium")
    low = sum(1 for t in threats if t["severity"] == "low")
    total = len(threats)
    active = sum(1 for t in threats if t["status"] == "active")
    unassigned = sum(1 for t in threats if not t.get("assignee"))
    risk_scores = [t["risk_score"] for t in threats]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0

    # Trend data — 30 days
    trend_data = []
    for d in range(30):
        date = (now - timedelta(days=29 - d)).strftime("%Y-%m-%d")
        dc = random.randint(0, 2)
        dh = random.randint(1, 5)
        dm = random.randint(3, 10)
        dl = random.randint(2, 6)
        trend_data.append({
            "date": date,
            "critical": dc,
            "high": dh,
            "medium": dm,
            "low": dl,
            "total": dc + dh + dm + dl,
        })

    # MITRE matrix — group techniques by tactic
    mitre_matrix = {}
    for tech in MITRE_TECHNIQUES:
        tactic = tech["tactic"]
        if tactic not in mitre_matrix:
            mitre_matrix[tactic] = []
        matching = [t for t in threats if t["mitreTechnique"] == tech["id"]]
        if matching:
            top_sev = "critical" if any(t["severity"] == "critical" for t in matching) else (
                "high" if any(t["severity"] == "high" for t in matching) else "medium"
            )
        else:
            top_sev = "medium"
        mitre_matrix[tactic].append({
            "id": tech["id"],
            "name": tech["name"],
            "severity": top_sev,
            "count": len(matching),
        })

    # Attack chains — 5 realistic multi-step paths
    attack_chains = [
        {
            "id": "chain-001",
            "name": "Public RDS to Data Exfiltration",
            "riskScore": 92,
            "steps": [
                {"technique": "T1190", "name": "Exploit Public-Facing Application", "resource": "arn:aws:rds:us-east-1:588989875114:db/prod-postgres"},
                {"technique": "T1078", "name": "Valid Accounts", "resource": "arn:aws:iam::588989875114:role/rds-admin-role"},
                {"technique": "T1530", "name": "Data from Cloud Storage", "resource": "arn:aws:s3:::prod-data-backup"},
                {"technique": "T1537", "name": "Transfer Data to Cloud Account", "resource": "arn:aws:s3:::prod-data-backup"},
            ],
            "resources": [
                "arn:aws:rds:us-east-1:588989875114:db/prod-postgres",
                "arn:aws:iam::588989875114:role/rds-admin-role",
                "arn:aws:s3:::prod-data-backup",
            ],
            "severity": "critical",
            "account": "588989875114",
        },
        {
            "id": "chain-002",
            "name": "IAM Privilege Escalation to Admin",
            "riskScore": 88,
            "steps": [
                {"technique": "T1078", "name": "Valid Accounts", "resource": "arn:aws:iam::312456789012:user/developer-01"},
                {"technique": "T1098", "name": "Account Manipulation", "resource": "arn:aws:iam::312456789012:policy/dev-policy"},
                {"technique": "T1136", "name": "Create Account", "resource": "arn:aws:iam::312456789012:user/backdoor-admin"},
            ],
            "resources": [
                "arn:aws:iam::312456789012:user/developer-01",
                "arn:aws:iam::312456789012:policy/dev-policy",
                "arn:aws:iam::312456789012:user/backdoor-admin",
            ],
            "severity": "critical",
            "account": "312456789012",
        },
        {
            "id": "chain-003",
            "name": "Credential Theft via EC2 Metadata",
            "riskScore": 78,
            "steps": [
                {"technique": "T1552", "name": "Unsecured Credentials", "resource": "arn:aws:ec2:us-west-2:588989875114:instance/i-0a1b2c3d4e5f67890"},
                {"technique": "T1087", "name": "Account Discovery", "resource": "arn:aws:iam::588989875114:role/ec2-instance-role"},
                {"technique": "T1530", "name": "Data from Cloud Storage", "resource": "arn:aws:s3:::internal-config-bucket"},
            ],
            "resources": [
                "arn:aws:ec2:us-west-2:588989875114:instance/i-0a1b2c3d4e5f67890",
                "arn:aws:iam::588989875114:role/ec2-instance-role",
                "arn:aws:s3:::internal-config-bucket",
            ],
            "severity": "high",
            "account": "588989875114",
        },
        {
            "id": "chain-004",
            "name": "EKS Lateral Movement to Data Store",
            "riskScore": 82,
            "steps": [
                {"technique": "T1190", "name": "Exploit Public-Facing Application", "resource": "arn:aws:eks:ap-south-1:198765432109:cluster/dev-cluster"},
                {"technique": "T1580", "name": "Cloud Infrastructure Discovery", "resource": "arn:aws:eks:ap-south-1:198765432109:cluster/dev-cluster"},
                {"technique": "T1530", "name": "Data from Cloud Storage", "resource": "arn:aws:dynamodb:ap-south-1:198765432109:table/user-sessions"},
            ],
            "resources": [
                "arn:aws:eks:ap-south-1:198765432109:cluster/dev-cluster",
                "arn:aws:dynamodb:ap-south-1:198765432109:table/user-sessions",
            ],
            "severity": "high",
            "account": "198765432109",
        },
        {
            "id": "chain-005",
            "name": "Lambda Privilege Escalation to KMS",
            "riskScore": 74,
            "steps": [
                {"technique": "T1078", "name": "Valid Accounts", "resource": "arn:aws:lambda:eu-west-1:312456789012:function/data-processor"},
                {"technique": "T1098", "name": "Account Manipulation", "resource": "arn:aws:iam::312456789012:role/lambda-exec-role"},
                {"technique": "T1485", "name": "Data Destruction", "resource": "arn:aws:kms:eu-west-1:312456789012:key/mrk-a1b2c3d4e5f6"},
            ],
            "resources": [
                "arn:aws:lambda:eu-west-1:312456789012:function/data-processor",
                "arn:aws:iam::312456789012:role/lambda-exec-role",
                "arn:aws:kms:eu-west-1:312456789012:key/mrk-a1b2c3d4e5f6",
            ],
            "severity": "high",
            "account": "312456789012",
        },
    ]

    # Account heatmap
    account_heatmap = []
    for acct in ACCOUNTS:
        acct_threats = [t for t in threats if t["account"] == acct["account_id"]]
        account_heatmap.append({
            "account": acct["account_id"],
            "critical": sum(1 for t in acct_threats if t["severity"] == "critical"),
            "high": sum(1 for t in acct_threats if t["severity"] == "high"),
            "medium": sum(1 for t in acct_threats if t["severity"] == "medium"),
            "low": sum(1 for t in acct_threats if t["severity"] == "low"),
            "total": len(acct_threats),
        })

    mitre_count = sum(len(v) for v in mitre_matrix.values())

    return {
        "pageContext": {
            "title": "Threat Detection",
            "brief": f"{total} threats detected with MITRE ATT&CK mapping",
            "details": [
                "Detects threats using rule-based analysis mapped to MITRE ATT&CK framework",
                "Risk scoring (0-100) based on severity, blast radius, and exploitability",
                "Toxic combination detection — multiple findings that compound into higher risk",
                "Attack path visualization from initial access to impact",
                "Threat timeline shows detection history across scan cycles",
            ],
            "tabs": [
                {"id": "overview", "label": "Overview", "count": total},
                {"id": "mitre", "label": "MITRE ATT&CK", "count": mitre_count},
                {"id": "attack_paths", "label": "Attack Paths", "count": len(attack_chains)},
                {"id": "timeline", "label": "Timeline", "count": len(trend_data)},
            ],
        },
        "filterSchema": [
            {"key": "severity", "label": "Severity", "type": "enum", "operators": ["is", "is_not", "in", "not_in"], "values": ["critical", "high", "medium", "low", "info"]},
            {"key": "rule_id", "label": "Rule ID", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "mitre_technique", "label": "MITRE Technique", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "mitre_tactic", "label": "MITRE Tactic", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "resource_type", "label": "Resource Type", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "resource_uid", "label": "Resource ARN", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "account_id", "label": "Account", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "region", "label": "Region", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "risk_score", "label": "Risk Score", "type": "number", "operators": ["eq", "neq", "gt", "gte", "lt", "lte"]},
        ],
        "kpiGroups": [
            {
                "title": "Threat Severity",
                "items": [
                    {"label": "Critical", "value": critical},
                    {"label": "High", "value": high},
                    {"label": "Medium", "value": medium},
                    {"label": "Low", "value": low},
                    {"label": "Total", "value": total},
                ],
            },
            {
                "title": "Threat Intelligence",
                "items": [
                    {"label": "MITRE Techniques", "value": mitre_count},
                    {"label": "Attack Paths", "value": len(attack_chains)},
                    {"label": "Avg Risk Score", "value": avg_risk, "suffix": "/100"},
                    {"label": "Active", "value": active},
                    {"label": "Total Findings", "value": sum(t["finding_count"] for t in threats)},
                ],
            },
        ],
        "scanMeta": {
            "scanRunId": "mock-scan-run-001",
            "latestDetection": threats[0]["detected"] if threats else "",
            "dataScope": "all_scans",
        },
        "threats": threats,
        "total": total,
        "trendData": trend_data,
        "mitreMatrix": mitre_matrix,
        "attackChains": attack_chains,
        "threatIntel": [],
        "accountHeatmap": account_heatmap,
        "kpi": {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "active": active,
            "unassigned": unassigned,
            "avgRiskScore": avg_risk,
        },
    }


# ── 2. Compliance ────────────────────────────────────────────────────────────

_FRAMEWORKS = [
    {"id": "cis-aws-2.0", "name": "CIS AWS 2.0", "short": "CIS", "controls": 180, "score": 82},
    {"id": "nist-800-53", "name": "NIST 800-53 r5", "short": "NIST", "controls": 154, "score": 76},
    {"id": "soc2-type2", "name": "SOC 2 Type II", "short": "SOC2", "controls": 64, "score": 88},
    {"id": "pci-dss-4.0", "name": "PCI DSS 4.0", "short": "PCI", "controls": 78, "score": 71},
    {"id": "hipaa", "name": "HIPAA", "short": "HIPAA", "controls": 44, "score": 85},
    {"id": "iso-27001", "name": "ISO 27001:2022", "short": "ISO", "controls": 93, "score": 79},
    {"id": "gdpr", "name": "GDPR", "short": "GDPR", "controls": 32, "score": 91},
]

_FAILING_CONTROL_TITLES = [
    ("CIS-2.1.1", "Ensure S3 Bucket Policy does not grant public read access", "CIS AWS 2.0", "s3"),
    ("CIS-1.4", "Ensure no root account access key exists", "CIS AWS 2.0", "iam"),
    ("CIS-1.10", "Ensure MFA is enabled for all IAM users with console access", "CIS AWS 2.0", "iam"),
    ("CIS-2.3.1", "Ensure RDS instances are not publicly accessible", "CIS AWS 2.0", "rds"),
    ("CIS-3.1", "Ensure CloudTrail is enabled in all regions", "CIS AWS 2.0", "cloudtrail"),
    ("NIST-AC-2", "Account Management — remove unused IAM credentials", "NIST 800-53 r5", "iam"),
    ("NIST-SC-8", "Transmission Confidentiality — enforce TLS on all endpoints", "NIST 800-53 r5", "ec2"),
    ("NIST-AU-2", "Audit Events — enable logging on all critical services", "NIST 800-53 r5", "cloudtrail"),
    ("SOC2-CC6.1", "Logical and Physical Access Controls — restrict admin access", "SOC 2 Type II", "iam"),
    ("SOC2-CC7.2", "System Operations — monitor for unauthorized changes", "SOC 2 Type II", "cloudtrail"),
    ("PCI-1.3.1", "Restrict inbound traffic to cardholder data environment", "PCI DSS 4.0", "ec2"),
    ("PCI-3.4", "Render PAN unreadable using encryption", "PCI DSS 4.0", "rds"),
    ("PCI-8.2.1", "Use unique IDs for all user access to system components", "PCI DSS 4.0", "iam"),
    ("HIPAA-164.312a1", "Access Control — implement technical policies for access", "HIPAA", "iam"),
    ("HIPAA-164.312e1", "Transmission Security — encrypt ePHI in transit", "HIPAA", "ec2"),
    ("ISO-A.8.24", "Use of Cryptography — encrypt data at rest and in transit", "ISO 27001:2022", "kms"),
    ("ISO-A.8.9", "Configuration Management — baseline and harden configurations", "ISO 27001:2022", "ec2"),
    ("GDPR-Art.32", "Security of Processing — encryption and pseudonymisation", "GDPR", "s3"),
    ("GDPR-Art.25", "Data Protection by Design — minimize data collection", "GDPR", "rds"),
    ("CIS-4.1", "Ensure Security Groups do not allow unrestricted ingress to port 22", "CIS AWS 2.0", "ec2"),
]


def mock_compliance() -> dict:
    """Mock response for /api/v1/views/compliance."""
    random.seed(42)

    frameworks = []
    for fw in _FRAMEWORKS:
        passed = int(fw["controls"] * fw["score"] / 100)
        failed = fw["controls"] - passed
        frameworks.append({
            "id": fw["id"],
            "name": fw["name"],
            "score": fw["score"],
            "controls": fw["controls"],
            "passed": passed,
            "failed": failed,
            "last_assessed": (now - timedelta(hours=random.randint(2, 48))).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })

    total_passed = sum(fw["passed"] for fw in frameworks)
    total_failed = sum(fw["failed"] for fw in frameworks)
    total_controls = total_passed + total_failed
    pass_rate = round((total_passed / total_controls) * 100, 1) if total_controls > 0 else 0
    overall_score = 78

    failing_controls = []
    for ctrl_id, title, framework, service in _FAILING_CONTROL_TITLES:
        acct = random.choice(ACCOUNTS)
        region = random.choice(REGIONS)
        sev = random.choice(["critical", "critical", "high", "high", "high", "medium"])
        failing_controls.append({
            "control_id": ctrl_id,
            "title": title,
            "framework": framework,
            "account": acct["account_id"],
            "region": region,
            "severity": sev,
            "total_failed": random.randint(2, 35),
            "days_open": random.randint(1, 120),
        })

    # 12-month trend
    trend_data = []
    base_score = 62
    for m in range(12):
        date = (now - timedelta(days=(11 - m) * 30)).strftime("%Y-%m-%d")
        base_score = min(95, base_score + random.uniform(0.5, 2.5))
        trend_data.append({"date": date, "score": round(base_score, 1)})

    # Audit deadlines
    audit_deadlines = [
        {"framework": "PCI DSS 4.0", "type": "Annual Compliance Audit", "due_date": (now + timedelta(days=45)).isoformat(), "days_remaining": 45, "owner": "Compliance Team", "status": "at-risk"},
        {"framework": "SOC 2 Type II", "type": "SOC 2 Audit Period End", "due_date": (now + timedelta(days=72)).isoformat(), "days_remaining": 72, "owner": "Security Team", "status": "on-track"},
        {"framework": "HIPAA", "type": "HIPAA Risk Assessment", "due_date": (now + timedelta(days=90)).isoformat(), "days_remaining": 90, "owner": "Compliance Team", "status": "on-track"},
        {"framework": "ISO 27001:2022", "type": "Surveillance Audit", "due_date": (now + timedelta(days=130)).isoformat(), "days_remaining": 130, "owner": "ISMS Manager", "status": "on-track"},
        {"framework": "GDPR", "type": "DPA Review", "due_date": (now + timedelta(days=180)).isoformat(), "days_remaining": 180, "owner": "DPO", "status": "on-track"},
    ]

    # Exceptions
    exceptions = [
        {
            "id": "exc-001",
            "control_id": "CIS-2.1.1",
            "framework": "CIS AWS 2.0",
            "reason": "Public website assets bucket — approved by CISO",
            "approved_by": "ciso@example.com",
            "expires": (now + timedelta(days=60)).strftime("%Y-%m-%d"),
            "status": "active",
        },
        {
            "id": "exc-002",
            "control_id": "PCI-1.3.1",
            "framework": "PCI DSS 4.0",
            "reason": "Legacy payment gateway requires direct access — migration scheduled Q3",
            "approved_by": "vp-engineering@example.com",
            "expires": (now + timedelta(days=120)).strftime("%Y-%m-%d"),
            "status": "active",
        },
        {
            "id": "exc-003",
            "control_id": "NIST-SC-8",
            "framework": "NIST 800-53 r5",
            "reason": "Internal service mesh uses mTLS — external TLS pending cert rotation",
            "approved_by": "security-lead@example.com",
            "expires": (now + timedelta(days=30)).strftime("%Y-%m-%d"),
            "status": "active",
        },
    ]

    # Account matrix — 3 accounts x 7 frameworks
    matrix_keys = ["CIS", "NIST", "SOC2", "PCI", "HIPAA", "ISO", "GDPR"]
    fw_score_map = {fw["short"]: fw["score"] for fw in _FRAMEWORKS}
    account_matrix = []
    for acct in ACCOUNTS:
        row = {
            "account": acct["account_name"],
            "account_id": acct["account_id"],
            "provider": "AWS",
            "environment": "production" if "prod" in acct["account_name"] else "development",
            "cred_expired": False,
            "status": "active",
        }
        for mk in matrix_keys:
            aid = acct["account_id"]
            seed = hashlib.md5(f"{aid}:{mk}".encode()).hexdigest()
            variance_pct = 5 + (int(seed[:4], 16) % 11)
            direction = 1 if int(seed[4], 16) % 2 == 0 else -1
            base = fw_score_map.get(mk, overall_score)
            adjusted = base + direction * (base * variance_pct / 100)
            row[mk] = round(max(0, min(100, adjusted)), 1)
        scores = [row[k] for k in matrix_keys if row.get(k, 0) > 0]
        row["avg"] = round(sum(scores) / len(scores), 1) if scores else 0
        account_matrix.append(row)

    critical_failures = sum(1 for c in failing_controls if c["severity"] == "critical")
    at_risk_count = sum(1 for fw in frameworks if fw["score"] < 70)

    return {
        "pageContext": {
            "title": "Compliance",
            "brief": f"{pass_rate}% pass rate — {total_passed} passed, {total_failed} failed across {len(frameworks)} frameworks",
            "details": [
                "Evaluates resources against 13+ compliance frameworks (CIS, NIST, ISO 27001, PCI-DSS, HIPAA, GDPR, SOC 2)",
                "Maps check findings to specific framework controls",
                "Track compliance score trends across scan cycles",
                "Export compliance reports for auditors in PDF/CSV format",
                "Review failing controls sorted by severity and affected resource count",
            ],
            "tabs": [
                {"id": "overview", "label": "Overview", "count": total_controls},
                {"id": "frameworks", "label": "Frameworks", "count": len(frameworks)},
                {"id": "controls", "label": "Failing Controls", "count": len(failing_controls)},
                {"id": "matrix", "label": "Account Matrix", "count": len(account_matrix)},
            ],
        },
        "filterSchema": [
            {"key": "severity", "label": "Severity", "type": "enum", "operators": ["is", "is_not", "in", "not_in"], "values": ["critical", "high", "medium", "low", "info"]},
            {"key": "status", "label": "Status", "type": "enum", "operators": ["is", "is_not", "in", "not_in"], "values": ["PASS", "FAIL"]},
            {"key": "framework_id", "label": "Framework", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "control_id", "label": "Control ID", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "rule_id", "label": "Rule ID", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "resource_type", "label": "Resource Type", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "resource_uid", "label": "Resource ARN", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "account_id", "label": "Account", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "region", "label": "Region", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
        ],
        "kpiGroups": [
            {
                "title": "Compliance Posture",
                "items": [
                    {"label": "Overall Score", "value": overall_score, "suffix": "%"},
                    {"label": "Pass Rate", "value": pass_rate, "suffix": "%"},
                    {"label": "Frameworks", "value": len(frameworks)},
                    {"label": "At Risk", "value": at_risk_count},
                ],
            },
            {
                "title": "Control Status",
                "items": [
                    {"label": "Total Controls", "value": total_controls},
                    {"label": "Passed", "value": total_passed},
                    {"label": "Failed", "value": total_failed},
                    {"label": "Critical Gaps", "value": critical_failures},
                ],
            },
        ],
        "frameworks": frameworks,
        "failingControls": failing_controls,
        "trendData": trend_data,
        "auditDeadlines": audit_deadlines,
        "exceptions": exceptions,
        "accountMatrix": account_matrix,
    }


# ── 3. Misconfigurations ────────────────────────────────────────────────────

_MISCONFIG_TITLES = [
    ("aws.s3.encryption.default", "S3 bucket default encryption not enabled", "s3", "encryption", "Data Protection"),
    ("aws.s3.public_access.block", "S3 bucket public access block not configured", "s3", "public_access", "Data Protection"),
    ("aws.s3.versioning.enabled", "S3 bucket versioning not enabled", "s3", "versioning", "Data Protection"),
    ("aws.s3.logging.enabled", "S3 bucket server access logging disabled", "s3", "logging", "Logging & Monitoring"),
    ("aws.iam.mfa.console_users", "IAM user with console access missing MFA", "iam", "mfa", "Identity & Access"),
    ("aws.iam.password.policy_length", "IAM password policy minimum length below 14 characters", "iam", "password_policy", "Identity & Access"),
    ("aws.iam.access_key.rotation", "IAM access key not rotated in 90+ days", "iam", "access_key", "Identity & Access"),
    ("aws.iam.policy.admin_star", "IAM policy grants full administrative privileges (*:*)", "iam", "policy", "Identity & Access"),
    ("aws.ec2.sg.unrestricted_ssh", "Security group allows unrestricted SSH access (0.0.0.0/0:22)", "ec2", "security_group", "Network"),
    ("aws.ec2.sg.unrestricted_rdp", "Security group allows unrestricted RDP access (0.0.0.0/0:3389)", "ec2", "security_group", "Network"),
    ("aws.ec2.imdsv2.required", "EC2 instance not enforcing IMDSv2", "ec2", "metadata", "Compute"),
    ("aws.ec2.ebs.encryption", "EBS volume encryption not enabled", "ec2", "encryption", "Data Protection"),
    ("aws.rds.public_access.disabled", "RDS instance is publicly accessible", "rds", "public_access", "Data Protection"),
    ("aws.rds.encryption.at_rest", "RDS instance encryption at rest not enabled", "rds", "encryption", "Data Protection"),
    ("aws.rds.backup.retention", "RDS automated backup retention less than 7 days", "rds", "backup", "Data Protection"),
    ("aws.rds.multi_az.enabled", "RDS instance not configured for Multi-AZ deployment", "rds", "availability", "Reliability"),
    ("aws.cloudtrail.enabled.all_regions", "CloudTrail not enabled in all regions", "cloudtrail", "logging", "Logging & Monitoring"),
    ("aws.cloudtrail.log_validation", "CloudTrail log file validation not enabled", "cloudtrail", "integrity", "Logging & Monitoring"),
    ("aws.kms.rotation.enabled", "KMS customer-managed key rotation not enabled", "kms", "key_management", "Data Protection"),
    ("aws.lambda.function.public", "Lambda function resource policy allows public invocation", "lambda", "public_access", "Compute"),
    ("aws.eks.endpoint.public", "EKS cluster API endpoint is publicly accessible", "eks", "public_access", "Compute"),
    ("aws.eks.logging.audit", "EKS cluster audit logging not enabled", "eks", "logging", "Logging & Monitoring"),
    ("aws.dynamodb.encryption.default", "DynamoDB table using default encryption instead of CMK", "dynamodb", "encryption", "Data Protection"),
    ("aws.dynamodb.pitr.enabled", "DynamoDB point-in-time recovery not enabled", "dynamodb", "backup", "Data Protection"),
    ("aws.sqs.encryption.enabled", "SQS queue server-side encryption not enabled", "sqs", "encryption", "Data Protection"),
    ("aws.sns.encryption.enabled", "SNS topic encryption not enabled", "sns", "encryption", "Data Protection"),
    ("aws.elasticache.encryption.rest", "ElastiCache cluster encryption at rest not enabled", "elasticache", "encryption", "Data Protection"),
    ("aws.elasticache.encryption.transit", "ElastiCache cluster encryption in transit not enabled", "elasticache", "encryption", "Data Protection"),
    ("aws.redshift.encryption.enabled", "Redshift cluster not encrypted", "redshift", "encryption", "Data Protection"),
    ("aws.redshift.public_access", "Redshift cluster is publicly accessible", "redshift", "public_access", "Data Protection"),
    ("aws.secretsmanager.rotation", "Secrets Manager secret automatic rotation not configured", "secretsmanager", "rotation", "Identity & Access"),
    ("aws.ec2.sg.all_traffic", "Security group allows all inbound traffic (0.0.0.0/0:all)", "ec2", "security_group", "Network"),
    ("aws.iam.root.access_key", "Root account has active access keys", "iam", "root", "Identity & Access"),
    ("aws.iam.unused.credentials", "IAM credentials unused for 90+ days not disabled", "iam", "lifecycle", "Identity & Access"),
    ("aws.ec2.public_ip.auto_assign", "EC2 instances in public subnet with auto-assign public IP", "ec2", "network", "Network"),
    ("aws.rds.iam_auth.enabled", "RDS instance IAM database authentication not enabled", "rds", "access_control", "Identity & Access"),
    ("aws.lambda.runtime.eol", "Lambda function using end-of-life runtime", "lambda", "runtime", "Compute"),
    ("aws.ecs.task.host_network", "ECS task definition uses host network mode", "ecs", "network", "Network"),
    ("aws.cloudtrail.s3_delivery", "CloudTrail not delivering logs to S3 bucket", "cloudtrail", "delivery", "Logging & Monitoring"),
    ("aws.kms.key.deletion_scheduled", "KMS key scheduled for deletion within 30 days", "kms", "lifecycle", "Data Protection"),
    ("aws.sqs.cross_account", "SQS queue policy allows cross-account access", "sqs", "access_control", "Network"),
    ("aws.sns.public_subscription", "SNS topic allows public subscription", "sns", "public_access", "Network"),
    ("aws.ec2.detailed_monitoring", "EC2 instance detailed monitoring not enabled", "ec2", "monitoring", "Logging & Monitoring"),
    ("aws.s3.lifecycle.policy", "S3 bucket without lifecycle management policy", "s3", "lifecycle", "Data Protection"),
    ("aws.iam.role.trust_any", "IAM role trust policy allows any AWS account to assume", "iam", "trust_policy", "Identity & Access"),
    ("aws.rds.master.default_user", "RDS instance uses default master username", "rds", "credential", "Identity & Access"),
    ("aws.ecs.service.no_network_config", "ECS service without VPC network configuration", "ecs", "network", "Network"),
    ("aws.eks.secrets.encrypted", "EKS cluster secrets not encrypted with KMS", "eks", "encryption", "Data Protection"),
    ("aws.lambda.env.secrets", "Lambda function stores secrets in environment variables", "lambda", "secrets", "Identity & Access"),
    ("aws.iam.user.multiple_keys", "IAM user has multiple active access keys", "iam", "access_key", "Identity & Access"),
]

_COMPLIANCE_FRAMEWORKS_FOR_FINDINGS = [
    ["CIS AWS 2.0", "NIST 800-53"],
    ["CIS AWS 2.0", "PCI DSS 4.0"],
    ["NIST 800-53", "SOC 2 Type II"],
    ["HIPAA", "NIST 800-53"],
    ["CIS AWS 2.0"],
    ["ISO 27001", "GDPR"],
    ["PCI DSS 4.0", "SOC 2 Type II"],
]


def mock_misconfig() -> dict:
    """Mock response for /api/v1/views/misconfig."""
    random.seed(42)

    findings = []
    for i in range(50):
        rule_id, title, service, posture_category, domain = _MISCONFIG_TITLES[i % len(_MISCONFIG_TITLES)]
        acct = random.choice(ACCOUNTS)
        region = random.choice(REGIONS)
        sev = _severity_weight()
        risk = _risk_score_for_severity(sev)
        # 80% FAIL, 20% PASS
        status = "FAIL" if random.random() < 0.80 else "PASS"
        resource_name = f"{service}-{random.randint(1000, 9999)}"
        resource_uid = _random_arn(service, acct["account_id"], region, resource_name)
        finding_id = _make_finding_id(rule_id, resource_uid, acct["account_id"], region)
        auto_remediable = random.random() < 0.35
        created_at = _past_date(90)
        age_days = (now - datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")).days

        findings.append({
            "finding_id": finding_id,
            "rule_id": rule_id,
            "title": title,
            "severity": sev,
            "status": status,
            "service": service,
            "provider": "AWS",
            "account_id": acct["account_id"],
            "region": region,
            "resource_uid": resource_uid,
            "posture_category": posture_category,
            "domain": domain,
            "risk_score": risk,
            "description": f"The {service} resource does not meet the security baseline for {posture_category}. {title.lower()}.",
            "remediation": _REMEDIATION_MAP.get(service, ["Review and remediate the finding"])[0],
            "compliance_frameworks": random.choice(_COMPLIANCE_FRAMEWORKS_FOR_FINDINGS),
            "auto_remediable": auto_remediable,
            "age_days": age_days,
            "sla_status": "breached" if (sev == "critical" and age_days > 1) or (sev == "high" and age_days > 7) else "within",
            "created_at": created_at,
        })

    total = len(findings)
    failed = sum(1 for f in findings if f["status"] == "FAIL")
    passed = total - failed
    critical = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low = sum(1 for f in findings if f["severity"] == "low")
    auto_remediable_count = sum(1 for f in findings if f.get("auto_remediable"))
    sla_breached = sum(1 for f in findings if f.get("sla_status") == "breached")
    ages = [f["age_days"] for f in findings]
    avg_age = round(sum(ages) / len(ages), 1) if ages else 0

    # Heatmap
    heatmap = []
    for acct in ACCOUNTS:
        acct_findings = [f for f in findings if f["account_id"] == acct["account_id"] and f["status"] == "FAIL"]
        heatmap.append({
            "account": acct["account_id"],
            "account_name": acct["account_name"],
            "critical": sum(1 for f in acct_findings if f["severity"] == "critical"),
            "high": sum(1 for f in acct_findings if f["severity"] == "high"),
            "medium": sum(1 for f in acct_findings if f["severity"] == "medium"),
            "low": sum(1 for f in acct_findings if f["severity"] == "low"),
            "total": len(acct_findings),
        })

    # Quick wins
    quick_wins = [f for f in findings if f["severity"] == "critical" and f.get("auto_remediable") and f["status"] == "FAIL"][:5]

    # By service
    by_service = {}
    for f in findings:
        svc = f.get("service", "other")
        by_service[svc] = by_service.get(svc, 0) + 1

    return {
        "pageContext": {
            "title": "Misconfigurations",
            "brief": f"{total} configuration findings across cloud resources",
            "details": [
                "Evaluates cloud resources against security best practice rules",
                "PASS/FAIL assessment for each rule-resource combination",
                "Severity-based prioritization — fix critical findings first",
                "Rule descriptions include remediation steps and framework mappings",
                "Group by service to identify the most misconfigured areas",
            ],
            "tabs": [
                {"id": "findings", "label": "Findings", "count": total},
                {"id": "heatmap", "label": "Heatmap", "count": len(heatmap)},
                {"id": "quick_wins", "label": "Quick Wins", "count": len(quick_wins)},
            ],
        },
        "filterSchema": [
            {"key": "severity", "label": "Severity", "type": "enum", "operators": ["is", "is_not", "in", "not_in"], "values": ["critical", "high", "medium", "low", "info"]},
            {"key": "status", "label": "Status", "type": "enum", "operators": ["is", "is_not", "in", "not_in"], "values": ["PASS", "FAIL"]},
            {"key": "rule_id", "label": "Rule ID", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "service", "label": "Service", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "resource_type", "label": "Resource Type", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "resource_uid", "label": "Resource ARN", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "account_id", "label": "Account", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
            {"key": "region", "label": "Region", "type": "string", "operators": ["is", "is_not", "contains", "not_contains", "starts_with"]},
        ],
        "kpiGroups": [
            {
                "title": "Finding Summary",
                "items": [
                    {"label": "Total Findings", "value": total},
                    {"label": "Critical", "value": critical},
                    {"label": "High", "value": high},
                    {"label": "Medium", "value": medium},
                ],
            },
            {
                "title": "Remediation",
                "items": [
                    {"label": "Auto-Remediable", "value": auto_remediable_count},
                    {"label": "Avg Age", "value": avg_age, "suffix": " days"},
                    {"label": "SLA Breached", "value": sla_breached},
                    {"label": "Quick Wins", "value": len(quick_wins)},
                ],
            },
        ],
        "findings": findings,
        "heatmap": heatmap,
        "quickWins": quick_wins,
        "byService": by_service,
        "kpi": {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "failed": failed,
            "passed": passed,
            "auto_remediable": auto_remediable_count,
            "avg_age": avg_age,
            "sla_breached": sla_breached,
        },
    }


# ── 4. Dashboard ─────────────────────────────────────────────────────────────

_MITRE_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#8b5cf6"]

_SLA_TARGETS = {"critical": "4h", "high": "24h", "medium": "7d", "low": "30d"}


def mock_dashboard() -> dict:
    """Mock response for /api/v1/views/dashboard."""
    random.seed(42)

    # Pull data from other mocks to keep consistent
    threat_resp = mock_threats()
    compliance_resp = mock_compliance()
    misconfig_resp = mock_misconfig()

    threat_kpi = threat_resp["kpi"]
    compliance_score = 78
    total_assets = 1847

    by_sev = {
        "critical": threat_kpi["critical"],
        "high": threat_kpi["high"],
        "medium": threat_kpi["medium"],
        "low": threat_kpi["low"],
    }

    total_threats = threat_kpi["total"]
    crit_count = by_sev["critical"]
    high_count = by_sev["high"]

    # KPI strip
    kpi = {
        "totalAssets": total_assets,
        "totalAssetsChange": 23,
        "openFindings": total_threats,
        "openFindingsChange": -5,
        "criticalHighFindings": crit_count + high_count,
        "criticalHighFindingsChange": -2,
        "complianceScore": compliance_score,
        "complianceScoreChange": 1.5,
        "financialRiskExposure": 72,
        "financialRiskExposureChange": -3,
        "attackSurfaceScore": 72,
        "attackSurfaceScoreChange": -3,
        "mttr": 3.2,
        "mttrChange": -0.4,
        "activeThreats": total_threats,
        "activeThreatsChange": -5,
        "slaCompliance": 76.4,
        "slaComplianceChange": 2.1,
        "internetExposed": 7,
    }

    # Severity chart (donut)
    sev_chart = [
        {"name": "Critical", "value": by_sev["critical"], "color": "#ef4444"},
        {"name": "High", "value": by_sev["high"], "color": "#f97316"},
        {"name": "Medium", "value": by_sev["medium"], "color": "#eab308"},
        {"name": "Low", "value": by_sev["low"], "color": "#22c55e"},
    ]

    # Compliance frameworks for dashboard
    frameworks = []
    for fw in _FRAMEWORKS:
        frameworks.append({
            "name": fw["name"],
            "score": fw["score"],
            "trend": round(random.uniform(-2.0, 3.0), 1),
        })

    # Security score trend (90d)
    security_score_trend = []
    score_val = 68.0
    for d in range(90):
        date = (now - timedelta(days=89 - d)).strftime("%Y-%m-%d")
        score_val = max(55, min(95, score_val + random.uniform(-1.0, 1.5)))
        event = None
        if d == 30:
            event = "Enabled CloudTrail in all regions"
        elif d == 60:
            event = "IAM MFA enforcement rollout"
        security_score_trend.append({"date": date, "score": round(score_val, 1), "event": event})

    # Threat activity trend (30d)
    threat_activity_trend = []
    for d in range(30):
        date = (now - timedelta(days=29 - d)).strftime("%Y-%m-%d")
        threats_val = random.randint(8, 32)
        threat_activity_trend.append({"date": date, "threats": threats_val})

    # Cloud providers
    cloud_providers = [
        {
            "name": "AWS",
            "accounts": 3,
            "resources": total_assets,
            "findings": total_threats,
            "compliance": compliance_score,
            "severities": by_sev,
        },
    ]

    # Cloud health grid
    cloud_health = [
        {
            "provider": "AWS",
            "accounts": 3,
            "resources": total_assets,
            "findings": total_threats,
            "compliance": compliance_score,
            "lastScan": "4h ago",
            "credStatus": "valid",
            "criticalFindings": crit_count,
            "highFindings": high_count,
        },
    ]

    # MITRE top 5 techniques
    mitre_counter = {}
    for t in threat_resp["threats"]:
        tech = t["mitreTechnique"]
        mitre_counter[tech] = mitre_counter.get(tech, 0) + 1
    sorted_mitre = sorted(mitre_counter.items(), key=lambda x: x[1], reverse=True)[:5]
    mitre_techniques = []
    mitre_name_map = {m["id"]: m["name"] for m in MITRE_TECHNIQUES}
    for i, (tech_id, count) in enumerate(sorted_mitre):
        mitre_techniques.append({
            "id": tech_id,
            "name": mitre_name_map.get(tech_id, tech_id),
            "count": count,
            "color": _MITRE_COLORS[i % len(_MITRE_COLORS)],
        })

    # Findings by category
    category_map = {
        "Identity & Access": {"critical": 2, "high": 4, "medium": 6, "low": 3},
        "Data Protection": {"critical": 1, "high": 3, "medium": 8, "low": 4},
        "Network": {"critical": 1, "high": 2, "medium": 4, "low": 2},
        "Logging & Monitoring": {"critical": 0, "high": 2, "medium": 3, "low": 1},
        "Compute": {"critical": 0, "high": 1, "medium": 3, "low": 2},
    }
    findings_by_category = sorted(
        [{"category": cat, **counts} for cat, counts in category_map.items()],
        key=lambda x: x["critical"] + x["high"],
        reverse=True,
    )

    # Attack surface
    attack_surface = [
        {"category": "S3 Buckets", "value": 14, "severity": "critical"},
        {"category": "EC2 Instances", "value": 9, "severity": "high"},
        {"category": "RDS Databases", "value": 6, "severity": "high"},
        {"category": "Lambda Functions", "value": 4, "severity": "high"},
        {"category": "EKS Clusters", "value": 3, "severity": "high"},
        {"category": "IAM Roles", "value": 8, "severity": "critical"},
        {"category": "SQS Queues", "value": 2, "severity": "high"},
    ]

    # Toxic combinations
    toxic_combos = [
        {
            "id": "arn:aws:rds:us-east-1:588989875114:db/prod-postgres",
            "riskScore": 95,
            "title": "prod-postgres",
            "provider": "AWS",
            "mitre": "T1190",
            "description": "5 overlapping threats detected on this resource.",
            "affectedResources": 5,
            "affectedAccounts": ["588989875114"],
            "fixLink": "/threats",
        },
        {
            "id": "arn:aws:s3:::prod-data-backup",
            "riskScore": 88,
            "title": "prod-data-backup",
            "provider": "AWS",
            "mitre": "T1530",
            "description": "4 overlapping threats detected on this resource.",
            "affectedResources": 4,
            "affectedAccounts": ["588989875114"],
            "fixLink": "/threats",
        },
        {
            "id": "arn:aws:iam::312456789012:user/developer-01",
            "riskScore": 82,
            "title": "developer-01",
            "provider": "AWS",
            "mitre": "T1098",
            "description": "3 overlapping threats detected on this resource.",
            "affectedResources": 3,
            "affectedAccounts": ["312456789012"],
            "fixLink": "/threats",
        },
    ]

    # Critical alerts
    critical_alerts = []
    crit_threats = [t for t in threat_resp["threats"] if t["severity"] in ("critical", "high")][:5]
    for i, t in enumerate(crit_threats):
        critical_alerts.append({
            "id": t["detection_id"],
            "message": t["title"],
            "resource": t["resource_uid"],
            "provider": "AWS",
            "timestamp": t["detected"],
            "count": t["finding_count"],
        })

    # Critical actions (3 urgency buckets)
    immediate = []
    this_week = []
    this_month = []
    for i, t in enumerate(threat_resp["threats"][:15]):
        sev = t["severity"]
        action = {
            "id": t["detection_id"],
            "severity": sev,
            "provider": "AWS",
            "title": t["title"],
            "affectedCount": t["finding_count"],
            "estimatedFix": "< 1h" if sev == "critical" else "2-4h" if sev == "high" else "1d",
            "link": "/threats",
        }
        if sev == "critical":
            immediate.append(action)
        elif sev == "high":
            this_week.append(action)
        else:
            this_month.append(action)

    # Remediation SLA
    remediation_sla = []
    for sev_name, count in by_sev.items():
        if count == 0:
            continue
        within = round(count * 0.75)
        remediation_sla.append({
            "severity": sev_name.capitalize(),
            "slaTarget": _SLA_TARGETS.get(sev_name, "30d"),
            "openCount": count,
            "withinSLA": within,
            "breached": count - within,
            "compliant": round((within / count) * 100, 1) if count > 0 else 100,
        })

    # Recent scans
    recent_scans = []
    for i, acct in enumerate(ACCOUNTS):
        recent_scans.append({
            "id": i + 1,
            "scanId": acct["account_id"][:12],
            "type": "Full",
            "provider": "AWS",
            "account": acct["account_name"],
            "started": (now - timedelta(hours=4 + i * 12)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration": f"{random.randint(12, 45)}m",
            "findings": random.randint(8, 25),
            "status": "active",
        })

    # Top risky resources
    risky_resources = [
        {"resource": "prod-postgres", "type": "rds", "provider": "AWS", "region": "us-east-1", "findings": 5, "riskScore": 95, "owner": "588989875114", "age": "32d"},
        {"resource": "prod-data-backup", "type": "s3", "provider": "AWS", "region": "us-east-1", "findings": 4, "riskScore": 88, "owner": "588989875114", "age": "45d"},
        {"resource": "developer-01", "type": "iam", "provider": "AWS", "region": "us-east-1", "findings": 3, "riskScore": 85, "owner": "312456789012", "age": "67d"},
        {"resource": "i-0a1b2c3d4e5f67890", "type": "ec2", "provider": "AWS", "region": "us-west-2", "findings": 4, "riskScore": 82, "owner": "588989875114", "age": "21d"},
        {"resource": "dev-cluster", "type": "eks", "provider": "AWS", "region": "ap-south-1", "findings": 3, "riskScore": 78, "owner": "198765432109", "age": "14d"},
        {"resource": "data-processor", "type": "lambda", "provider": "AWS", "region": "eu-west-1", "findings": 2, "riskScore": 74, "owner": "312456789012", "age": "28d"},
        {"resource": "prod-cache-001", "type": "elasticache", "provider": "AWS", "region": "us-east-1", "findings": 2, "riskScore": 68, "owner": "588989875114", "age": "38d"},
        {"resource": "staging-redshift", "type": "redshift", "provider": "AWS", "region": "us-west-2", "findings": 2, "riskScore": 65, "owner": "312456789012", "age": "52d"},
        {"resource": "order-queue", "type": "sqs", "provider": "AWS", "region": "us-east-1", "findings": 1, "riskScore": 55, "owner": "588989875114", "age": "19d"},
        {"resource": "notifications-topic", "type": "sns", "provider": "AWS", "region": "us-east-1", "findings": 1, "riskScore": 48, "owner": "588989875114", "age": "25d"},
    ]

    # Recent threats (top 10 from threat mock)
    recent_threats = threat_resp["threats"][:10]

    return {
        "pageContext": {
            "title": "Security Dashboard",
            "brief": f"Executive overview — {total_threats} findings, {total_assets} assets monitored",
            "details": [
                "Aggregated security posture across all engines and cloud accounts",
                "KPIs refresh with each scan — compliance, threats, misconfigurations, IAM, data security",
                "Click any widget to drill into the corresponding engine page",
                "Use the scope bar to filter by tenant, provider, account, or region",
            ],
            "tabs": [],
        },
        "kpi": kpi,
        "chartCategories": [
            {
                "id": "security_posture",
                "title": "Security Posture",
                "charts": [
                    {"id": "severity_donut", "type": "donut", "title": "Findings by Severity", "data": sev_chart},
                    {"id": "compliance_frameworks", "type": "horizontal_bar", "title": "Compliance by Framework", "data": frameworks},
                    {"id": "security_score_trend", "type": "line", "title": "Security Score Trend (90d)", "data": security_score_trend},
                ],
            },
            {
                "id": "threats",
                "title": "Threats",
                "charts": [
                    {"id": "mitre_top_techniques", "type": "bar", "title": "Top MITRE Techniques", "data": mitre_techniques},
                    {"id": "threat_activity_trend", "type": "area", "title": "Threat Activity (30d)", "data": threat_activity_trend},
                    {"id": "findings_by_category", "type": "stacked_bar", "title": "Findings by Category", "data": findings_by_category},
                ],
            },
            {
                "id": "assets",
                "title": "Assets & Infrastructure",
                "charts": [
                    {"id": "cloud_providers", "type": "cards", "title": "Cloud Providers", "data": cloud_providers},
                    {"id": "attack_surface", "type": "treemap", "title": "Attack Surface", "data": attack_surface},
                    {"id": "cloud_health", "type": "grid", "title": "Cloud Health", "data": cloud_health},
                ],
            },
            {
                "id": "operations",
                "title": "Operations & Remediation",
                "charts": [
                    {"id": "remediation_sla", "type": "table", "title": "Remediation SLA", "data": remediation_sla},
                    {"id": "recent_scans", "type": "table", "title": "Recent Scans", "data": recent_scans},
                    {"id": "risky_resources", "type": "table", "title": "Top Risky Resources", "data": risky_resources},
                ],
            },
        ],
        "criticalActions": {"immediate": immediate, "thisWeek": this_week, "thisMonth": this_month},
        "toxicCombinations": toxic_combos,
        "criticalAlerts": critical_alerts,
        "recentThreats": recent_threats,
    }


# ── 5. IAM ──────────────────────────────────────────────────────────────────

_IAM_USERNAMES = [
    "admin-ops", "deploy-bot", "jenkins-ci", "terraform-runner", "alice.eng",
    "bob.devops", "carol.sec", "david.analyst", "eve.readonly", "frank.admin",
    "grace.billing", "heidi.dev", "ivan.audit", "judy.platform", "karl.support",
]

_IAM_GROUPS = [
    ["Administrators"], ["Developers", "ReadOnly"], ["PowerUsers"],
    ["Billing"], ["SecurityAudit"], ["Developers"], ["ReadOnly"],
    ["Administrators", "Developers"], ["ReadOnly", "Billing"], ["PowerUsers", "SecurityAudit"],
]

_IAM_POLICIES = [
    ["AdministratorAccess"], ["PowerUserAccess", "IAMReadOnlyAccess"],
    ["AmazonS3FullAccess", "AmazonEC2ReadOnlyAccess"], ["ViewOnlyAccess"],
    ["SecurityAudit"], ["AmazonEKSClusterPolicy"], ["ReadOnlyAccess"],
    ["AWSLambda_FullAccess"], ["AmazonRDSFullAccess"], ["AmazonVPCFullAccess"],
]

_IAM_ROLE_RULES = [
    ("iam-role-admin-access", "IAM role has AdministratorAccess policy attached", "Remove AdministratorAccess and use least-privilege policies"),
    ("iam-role-wildcard-action", "IAM role allows wildcard (*) actions", "Scope actions to specific API calls needed"),
    ("iam-role-cross-account-trust", "IAM role trust policy allows external accounts", "Restrict trust to known account IDs only"),
    ("iam-role-no-boundary", "IAM role lacks a permissions boundary", "Attach a permissions boundary to limit effective permissions"),
    ("iam-role-service-linked-overprivileged", "Service-linked role exceeds minimal permissions", "Review and request AWS to scope down SLR"),
    ("iam-role-assume-any", "Role can be assumed by any authenticated AWS principal", "Restrict Principal to specific ARNs"),
    ("iam-role-unused-90d", "IAM role not used in last 90 days", "Delete or disable unused roles"),
    ("iam-role-inline-policy", "IAM role uses inline policy instead of managed", "Convert inline policies to managed for auditability"),
    ("iam-role-pass-role-star", "Role has iam:PassRole with * resource", "Scope PassRole to specific role ARNs"),
    ("iam-role-no-mfa-condition", "Role trust policy lacks MFA condition", "Add aws:MultiFactorAuthPresent condition"),
]

_IAM_ACCESS_KEY_RULES = [
    ("iam-key-age-90d", "Access key older than 90 days", "Rotate the access key and update dependent services"),
    ("iam-key-unused-30d", "Access key not used in last 30 days", "Deactivate or delete unused access keys"),
    ("iam-key-multiple-active", "User has multiple active access keys", "Deactivate redundant keys"),
    ("iam-key-root-active", "Root account has active access keys", "Remove root access keys and use IAM roles"),
    ("iam-key-no-last-used", "Access key has never been used since creation", "Delete the key if not needed"),
    ("iam-key-attached-to-admin", "Access key attached to admin-privileged user", "Move to a least-privilege service account"),
    ("iam-key-leaked-public", "Access key detected in public repository", "Immediately rotate and revoke the key"),
    ("iam-key-plaintext-config", "Access key stored in plaintext config file", "Move credentials to Secrets Manager or environment variables"),
]

_IAM_PRIV_ESC_RULES = [
    ("iam-privesc-create-policy", "User can create IAM policy and attach it to self", "Remove iam:CreatePolicy + iam:AttachUserPolicy combination"),
    ("iam-privesc-create-role-passrole", "User can create role and pass it to compute service", "Scope iam:CreateRole and iam:PassRole resources"),
    ("iam-privesc-lambda-exec", "User can create Lambda + pass role → execute as role", "Restrict lambda:CreateFunction and iam:PassRole"),
    ("iam-privesc-ssm-send-command", "User can send SSM commands to privileged instances", "Restrict ssm:SendCommand to specific instance tags"),
    ("iam-privesc-sts-assume-admin", "User can assume a role with admin privileges", "Add MFA condition and restrict sts:AssumeRole"),
]

_IAM_MODULES = [
    "password_policy", "access_keys", "mfa_compliance",
    "privilege_escalation", "cross_account_trust", "unused_identities",
]


def mock_iam() -> dict:
    """Mock response for /api/v1/views/iam."""
    random.seed(42)

    # ── identities ──
    identity_types = ["user", "role", "group", "federated_user", "service_account"]
    identities = []
    for i in range(15):
        acct = ACCOUNTS[i % len(ACCOUNTS)]
        username = _IAM_USERNAMES[i]
        sev = _severity_weight()
        id_type = identity_types[i % len(identity_types)]
        arn = _random_arn("iam", acct["account_id"], "global", f"{id_type}/{username}")
        identities.append({
            "id": arn,
            "username": username,
            "type": id_type,
            "provider": "aws",
            "account_id": acct["account_id"],
            "account_name": acct["account_name"],
            "groups": _IAM_GROUPS[i % len(_IAM_GROUPS)],
            "policies": _IAM_POLICIES[i % len(_IAM_POLICIES)],
            "last_login": _past_date(45),
            "mfa_enabled": random.random() > 0.25,
            "risk_score": _risk_score_for_severity(sev),
            "status": random.choice(["active"] * 8 + ["inactive"] * 2),
            "findings_count": random.randint(0, 12),
            "severity": sev,
        })

    # ── roles ──
    roles = []
    for i in range(10):
        rule_id, desc, remediation = _IAM_ROLE_RULES[i]
        acct = ACCOUNTS[i % len(ACCOUNTS)]
        region = random.choice(REGIONS)
        sev = _severity_weight()
        role_name = f"role-{random.choice(['admin', 'deploy', 'lambda-exec', 'ecs-task', 'cross-account', 'readonly', 'cicd', 'monitoring', 'backup', 'audit'])}-{random.randint(100, 999)}"
        resource_uid = _random_arn("iam", acct["account_id"], "global", f"role/{role_name}")
        roles.append({
            "name": role_name,
            "type": "role",
            "rule_id": rule_id,
            "severity": sev,
            "status": random.choice(["FAIL"] * 7 + ["PASS"] * 3),
            "resource_uid": resource_uid,
            "account_id": acct["account_id"],
            "region": "global",
            "description": desc,
            "remediation": remediation,
        })

    # ── accessKeys ──
    access_keys = []
    for i in range(8):
        rule_id, desc, remediation = _IAM_ACCESS_KEY_RULES[i]
        acct = ACCOUNTS[i % len(ACCOUNTS)]
        sev = _severity_weight()
        username = _IAM_USERNAMES[i % len(_IAM_USERNAMES)]
        key_id = f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}"
        resource_uid = _random_arn("iam", acct["account_id"], "global", f"user/{username}")
        access_keys.append({
            "key_id": key_id,
            "username": username,
            "rule_id": rule_id,
            "severity": sev,
            "status": "FAIL",
            "resource_uid": resource_uid,
            "account_id": acct["account_id"],
            "region": "global",
            "description": desc,
            "remediation": remediation,
            "created_at": _past_date(180),
            "last_used": _past_date(30) if random.random() > 0.3 else None,
        })

    # ── privilegeEscalation ──
    priv_esc = []
    for i in range(5):
        rule_id, desc, remediation = _IAM_PRIV_ESC_RULES[i]
        acct = ACCOUNTS[i % len(ACCOUNTS)]
        sev = random.choice(["critical", "high"])
        username = _IAM_USERNAMES[i]
        resource_uid = _random_arn("iam", acct["account_id"], "global", f"user/{username}")
        priv_esc.append({
            "rule_id": rule_id,
            "username": username,
            "severity": sev,
            "status": "FAIL",
            "resource_uid": resource_uid,
            "account_id": acct["account_id"],
            "region": "global",
            "description": desc,
            "remediation": remediation,
            "risk_score": _risk_score_for_severity(sev),
            "attack_vector": desc,
        })

    # ── findingsByModule ──
    findings_by_module = {
        "role_management": 10,
        "access_control": 8,
        "least_privilege": 5,
        "password_policy": 4,
    }

    mfa_count = sum(1 for u in identities if u.get("mfa_enabled"))
    mfa_pct = round(mfa_count / len(identities) * 100, 1) if identities else 0

    return {
        "pageContext": {
            "title": "IAM Security",
            "brief": "Identity and access management posture across cloud accounts. "
                     "Monitors roles, access keys, MFA adoption, and privilege escalation paths.",
            "tabs": [
                {"id": "overview",             "label": "Overview",             "count": len(identities)},
                {"id": "roles",                "label": "Roles & Policies",     "count": len(roles)},
                {"id": "access_keys",          "label": "Access Control",       "count": len(access_keys)},
                {"id": "privilege_escalation",  "label": "Privilege Escalation", "count": len(priv_esc)},
            ],
        },
        "kpiGroups": [
            {
                "title": "Identity Risk",
                "items": [
                    {"label": "Critical",       "value": sum(1 for u in identities if u["severity"] == "critical")},
                    {"label": "High",           "value": sum(1 for u in identities if u["severity"] == "high")},
                    {"label": "Medium",         "value": sum(1 for u in identities if u["severity"] == "medium")},
                    {"label": "Posture Score",  "value": 62, "suffix": "/100"},
                    {"label": "Total Findings", "value": sum(u["findings_count"] for u in identities)},
                ],
            },
            {
                "title": "Access Hygiene",
                "items": [
                    {"label": "MFA Adoption",   "value": mfa_pct, "suffix": "%"},
                    {"label": "Keys to Rotate", "value": len(access_keys)},
                    {"label": "Overprivileged", "value": 5},
                    {"label": "Identities",     "value": len(identities)},
                    {"label": "Modules",        "value": len(findings_by_module)},
                ],
            },
        ],
        "findingsByModule": findings_by_module,
        "identities": identities,
        "roles": roles,
        "accessKeys": access_keys,
        "privilegeEscalation": priv_esc,
    }


# ── 6. Inventory ────────────────────────────────────────────────────────────

_RESOURCE_TYPES = [
    ("ec2", "AWS::EC2::Instance", "i-"),
    ("s3", "AWS::S3::Bucket", ""),
    ("rds", "AWS::RDS::DBInstance", "db-"),
    ("lambda", "AWS::Lambda::Function", ""),
    ("iam", "AWS::IAM::Role", "role/"),
    ("ecs", "AWS::ECS::Service", "svc-"),
    ("eks", "AWS::EKS::Cluster", ""),
    ("dynamodb", "AWS::DynamoDB::Table", ""),
    ("sqs", "AWS::SQS::Queue", ""),
    ("sns", "AWS::SNS::Topic", ""),
    ("kms", "AWS::KMS::Key", "key-"),
    ("elasticache", "AWS::ElastiCache::Cluster", ""),
    ("redshift", "AWS::Redshift::Cluster", ""),
    ("secretsmanager", "AWS::SecretsManager::Secret", ""),
    ("cloudtrail", "AWS::CloudTrail::Trail", ""),
]

_RESOURCE_NAMES = [
    "web-server", "api-backend", "data-lake", "auth-service", "log-processor",
    "config-store", "event-bus", "cache-primary", "analytics-db", "ci-runner",
    "monitoring-agent", "backup-vault", "migration-worker", "gateway-proxy", "queue-handler",
    "stream-ingestor", "ml-training", "report-generator", "notification-hub", "audit-trail",
    "static-assets", "session-store", "etl-pipeline", "feature-flags", "rate-limiter",
    "dns-resolver", "cert-manager", "image-processor", "search-index", "task-scheduler",
    "payment-service", "user-profile", "document-store", "media-encoder", "health-checker",
    "webhook-relay", "secret-rotator", "cost-tracker", "compliance-scanner", "drift-detector",
    "asset-inventory", "policy-engine", "token-service", "graph-builder", "alert-router",
    "chaos-monkey", "canary-deploy", "blue-green-lb", "spot-manager", "capacity-planner",
    "perf-tester", "load-balancer", "cdn-origin", "api-key-store", "oidc-provider",
    "service-mesh", "sidecar-proxy", "log-aggregator", "metric-relay", "trace-collector",
]

_TAGS = [
    {"env": "production", "team": "platform"},
    {"env": "staging", "team": "backend"},
    {"env": "production", "team": "security"},
    {"env": "dev", "team": "frontend"},
    {"env": "production", "team": "data"},
    {"env": "staging", "team": "devops"},
    {},
]


def mock_inventory() -> dict:
    """Mock response for /api/v1/views/inventory."""
    random.seed(42)

    assets = []
    svc_counts = {}
    region_counts = {}

    for i in range(60):
        svc, rtype, prefix = _RESOURCE_TYPES[i % len(_RESOURCE_TYPES)]
        acct = ACCOUNTS[i % len(ACCOUNTS)]
        region = REGIONS[i % len(REGIONS)]
        name = _RESOURCE_NAMES[i % len(_RESOURCE_NAMES)]
        sev = _severity_weight()
        risk = _risk_score_for_severity(sev)
        resource_name = f"{prefix}{name}-{random.randint(1000, 9999)}"
        resource_uid = _random_arn(svc, acct["account_id"], region, resource_name)
        internet_exposed = random.random() < 0.15

        findings = {
            "critical": random.randint(0, 2) if sev == "critical" else 0,
            "high": random.randint(0, 3) if sev in ("critical", "high") else 0,
            "medium": random.randint(0, 4),
            "low": random.randint(0, 5),
        }

        exposure_types = {"ec2": "public_ip", "s3": "public_bucket", "elasticloadbalancingv2": "load_balancer",
                          "cloudfront": "cdn", "apigateway": "api_endpoint"}
        exposure_type = exposure_types.get(svc, "none") if internet_exposed else "none"

        assets.append({
            "resource_uid": resource_uid,
            "resource_name": resource_name,
            "resource_type": rtype,
            "service": svc,
            "provider": "AWS",
            "account_id": acct["account_id"],
            "region": region,
            "status": random.choice(["active"] * 8 + ["stopped"] * 1 + ["running"] * 1),
            "risk_score": risk,
            "severity": sev,
            "tags": _TAGS[i % len(_TAGS)],
            "findings": findings,
            "internet_exposed": internet_exposed,
            "internet_exposure": {"type": exposure_type, "exposed": internet_exposed},
            "created_at": _past_date(365),
            "last_scanned": _past_date(3),
            "config": {},
        })

        svc_counts[svc] = svc_counts.get(svc, 0) + 1
        region_counts[region] = region_counts.get(region, 0) + 1

    provider_counts = {"AWS": 60}
    exposed_count = sum(1 for a in assets if a["internet_exposed"])
    critical_count = sum(a["findings"]["critical"] for a in assets)

    summary = {
        "total_assets": len(assets),
        "total_relationships": 142,
        "total_drift": 8,
        "removed_assets": 3,
        "assets_by_provider": provider_counts,
        "assets_by_service": svc_counts,
        "assets_by_region": region_counts,
        "relationships_by_type": {
            "contains": 48, "connects_to": 35, "depends_on": 27,
            "secures": 18, "routes_to": 14,
        },
        "drift_by_type": {"modified": 5, "added": 2, "removed": 1},
    }

    return {
        "pageContext": {
            "title": "Asset Inventory",
            "brief": "Unified inventory of cloud resources with drift detection, "
                     "relationship mapping, and posture enrichment.",
            "tabs": [
                {"id": "assets",       "label": "Assets",       "count": len(assets)},
                {"id": "architecture", "label": "Architecture", "count": 0},
                {"id": "graph",        "label": "Graph",        "count": 0},
            ],
        },
        "kpiGroups": [
            {
                "title": "Asset Coverage",
                "items": [
                    {"label": "Total Assets", "value": len(assets)},
                    {"label": "Providers",    "value": len(provider_counts)},
                    {"label": "Regions",      "value": len(region_counts)},
                    {"label": "Services",     "value": len(svc_counts)},
                ],
            },
            {
                "title": "Asset Health",
                "items": [
                    {"label": "New This Week",     "value": 12},
                    {"label": "Drift Detected",    "value": 8},
                    {"label": "Exposed Assets",    "value": exposed_count},
                    {"label": "Critical Findings", "value": critical_count},
                ],
            },
        ],
        "assets": assets,
        "total": len(assets),
        "has_more": False,
        "summary": summary,
    }


# ── 7. CIEM ─────────────────────────────────────────────────────────────────

_CIEM_RULE_NAMES = [
    ("ciem-unused-permission", "Unused permissions detected", "identity_hygiene"),
    ("ciem-cross-account-role", "Cross-account role assumption without MFA", "cross_account"),
    ("ciem-wildcard-resource", "Wildcard resource in policy statement", "overprivilege"),
    ("ciem-admin-no-boundary", "Admin access without permissions boundary", "overprivilege"),
    ("ciem-stale-role-90d", "Role not assumed in 90+ days", "identity_hygiene"),
    ("ciem-service-last-accessed", "Service not accessed by granted permission", "least_privilege"),
    ("ciem-policy-version-old", "Policy uses outdated version (2012-10-17 only)", "policy_management"),
    ("ciem-assume-role-chain", "Role chaining depth exceeds 3 hops", "cross_account"),
    ("ciem-inline-allow-star", "Inline policy with Allow * effect", "overprivilege"),
    ("ciem-effective-admin", "Effective permissions grant admin via group inheritance", "overprivilege"),
    ("ciem-s3-public-policy-actor", "Actor can set S3 bucket policy to public", "data_access"),
    ("ciem-iam-user-direct-policy", "IAM user has directly attached policies", "policy_management"),
    ("ciem-federation-without-scope", "Federated identity has no session policy scope", "cross_account"),
    ("ciem-lambda-invoke-any", "Identity can invoke any Lambda function", "compute_access"),
    ("ciem-ec2-describe-all", "Identity has broad EC2 describe permissions", "least_privilege"),
    ("ciem-secrets-read-all", "Identity can read all Secrets Manager secrets", "data_access"),
    ("ciem-kms-decrypt-star", "Identity can decrypt with any KMS key", "data_access"),
    ("ciem-sts-assume-any", "Identity can assume any role via sts:AssumeRole *", "cross_account"),
    ("ciem-cloudformation-create", "Identity can create CloudFormation stacks (privilege escalation path)", "overprivilege"),
    ("ciem-ssm-run-command", "Identity can run SSM commands on any instance", "compute_access"),
    ("ciem-log-group-delete", "Identity can delete CloudWatch log groups", "defense_evasion"),
    ("ciem-trail-stop", "Identity can stop CloudTrail logging", "defense_evasion"),
    ("ciem-guardduty-disable", "Identity can disable GuardDuty detector", "defense_evasion"),
]

_CIEM_IDENTITY_NAMES = [
    "deploy-automation", "jenkins-prod", "terraform-state", "readonly-auditor",
    "admin-backup", "lambda-executor", "ecs-task-runner", "eks-node-role",
    "cross-account-audit", "ci-pipeline-bot", "data-scientist", "billing-viewer",
]

_CIEM_LOG_SOURCES = [
    {"name": "CloudTrail Management Events", "type": "cloudtrail", "status": "active", "events_24h": 142567, "coverage": 98.2},
    {"name": "CloudTrail Data Events (S3)", "type": "cloudtrail_data", "status": "active", "events_24h": 87432, "coverage": 76.5},
    {"name": "VPC Flow Logs", "type": "vpc_flow", "status": "active", "events_24h": 534210, "coverage": 91.0},
    {"name": "GuardDuty Findings", "type": "guardduty", "status": "active", "events_24h": 23, "coverage": 100.0},
]


def mock_ciem() -> dict:
    """Mock response for /api/v1/views/ciem — matches real BFF /ciem contract."""
    random.seed(42)

    acct0 = ACCOUNTS[0]["account_id"]
    acct1 = ACCOUNTS[1]["account_id"]
    acct2 = ACCOUNTS[2]["account_id"]

    # ── topCritical — 10 critical findings with required fields ───────────
    top_critical = [
        {"severity": "critical", "title": "Root account used for console login",
         "rule_id": "ciem-cloudtrail-001",
         "actor_principal": f"arn:aws:iam::{acct0}:root",
         "resource_uid": f"arn:aws:iam::{acct0}:root",
         "event_time": _past_date(1)},
        {"severity": "critical", "title": "IAM policy attached granting AdministratorAccess",
         "rule_id": "ciem-iam-002",
         "actor_principal": f"arn:aws:iam::{acct0}:user/deploy-bot",
         "resource_uid": f"arn:aws:iam::{acct0}:policy/AdminAccess",
         "event_time": _past_date(1)},
        {"severity": "critical", "title": "S3 bucket policy changed to public access",
         "rule_id": "ciem-s3-003",
         "actor_principal": f"arn:aws:iam::{acct1}:user/dev-lead",
         "resource_uid": f"arn:aws:s3:::data-lake-{acct1}",
         "event_time": _past_date(2)},
        {"severity": "critical", "title": "Security group rule added allowing 0.0.0.0/0 on port 22",
         "rule_id": "ciem-vpc-004",
         "actor_principal": f"arn:aws:iam::{acct0}:user/sre-oncall",
         "resource_uid": f"arn:aws:ec2:{REGIONS[3]}:{acct0}:security-group/sg-0a1b2c3d",
         "event_time": _past_date(2)},
        {"severity": "critical", "title": "KMS key deletion scheduled",
         "rule_id": "ciem-kms-005",
         "actor_principal": f"arn:aws:iam::{acct2}:user/admin-user",
         "resource_uid": f"arn:aws:kms:{REGIONS[0]}:{acct2}:key/mrk-abc123",
         "event_time": _past_date(3)},
        {"severity": "critical", "title": "CloudTrail logging disabled in production account",
         "rule_id": "ciem-ct-006",
         "actor_principal": f"arn:aws:iam::{acct0}:user/deploy-bot",
         "resource_uid": f"arn:aws:cloudtrail:{REGIONS[3]}:{acct0}:trail/prod-audit",
         "event_time": _past_date(3)},
        {"severity": "critical", "title": "Cross-account role assumed without external ID",
         "rule_id": "ciem-sts-007",
         "actor_principal": f"arn:aws:iam::{acct1}:role/cross-account-role",
         "resource_uid": f"arn:aws:iam::{acct0}:role/trusting-role",
         "event_time": _past_date(4)},
        {"severity": "critical", "title": "Lambda function code updated from untrusted source IP",
         "rule_id": "ciem-lambda-008",
         "actor_principal": f"arn:aws:iam::{acct0}:user/ci-runner",
         "resource_uid": f"arn:aws:lambda:{REGIONS[3]}:{acct0}:function:auth-handler",
         "event_time": _past_date(4)},
        {"severity": "critical", "title": "RDS snapshot shared with external account",
         "rule_id": "ciem-rds-009",
         "actor_principal": f"arn:aws:iam::{acct2}:user/data-analyst",
         "resource_uid": f"arn:aws:rds:{REGIONS[1]}:{acct2}:snapshot:prod-db-snap",
         "event_time": _past_date(5)},
        {"severity": "critical", "title": "EKS cluster endpoint made public",
         "rule_id": "ciem-eks-010",
         "actor_principal": f"arn:aws:iam::{acct0}:user/sre-oncall",
         "resource_uid": f"arn:aws:eks:{REGIONS[3]}:{acct0}:cluster/k8s-cluster",
         "event_time": _past_date(5)},
    ]

    # ── 12 identity risk entries ──────────────────────────────────────────
    _ident_data = [
        ("root",              95, 12, 4, 5, 8,  6, 15),
        ("deploy-automation", 88, 9,  3, 4, 12, 8, 22),
        ("jenkins-prod",      76, 7,  2, 3, 9,  5, 18),
        ("terraform-state",   72, 6,  2, 2, 7,  4, 12),
        ("admin-backup",      68, 5,  1, 3, 6,  5, 10),
        ("lambda-executor",   55, 4,  0, 2, 5,  4, 8),
        ("data-scientist",    48, 3,  0, 1, 4,  3, 6),
        ("ecs-task-runner",   42, 3,  0, 1, 3,  2, 5),
        ("eks-node-role",     35, 2,  0, 1, 2,  2, 4),
        ("cross-account-audit", 32, 2, 0, 1, 3, 3, 7),
        ("ci-pipeline-bot",   28, 2,  0, 0, 2,  1, 3),
        ("billing-viewer",    12, 1,  0, 0, 1,  1, 1),
    ]
    identities = []
    for i, (name, risk, total, crit, high, rules_triggered, svcs, resources) in enumerate(_ident_data):
        acct = ACCOUNTS[i % len(ACCOUNTS)]
        acct_id = acct["account_id"]
        kind = "root" if name == "root" else ("role" if "role" in name or "exec" in name or "runner" in name else "user")
        identities.append({
            "actor_principal": f"arn:aws:iam::{acct_id}:{kind}/{name}",
            "risk_score": risk,
            "total_findings": total,
            "critical": crit,
            "high": high,
            "rules_triggered": rules_triggered,
            "services_used": svcs,
            "resources_touched": resources,
        })

    # ── 8 top detection rules ─────────────────────────────────────────────
    top_rules = [
        {"rule_id": "ciem-cloudtrail-001", "severity": "critical", "title": "Root account activity detected",
         "finding_count": 12, "rule_source": "cloudtrail", "unique_actors": 1, "unique_resources": 8},
        {"rule_id": "ciem-iam-002", "severity": "critical", "title": "Administrative policy attachment",
         "finding_count": 9, "rule_source": "cloudtrail", "unique_actors": 3, "unique_resources": 5},
        {"rule_id": "ciem-s3-003", "severity": "critical", "title": "S3 bucket policy allows public access",
         "finding_count": 7, "rule_source": "cloudtrail", "unique_actors": 2, "unique_resources": 4},
        {"rule_id": "ciem-vpc-004", "severity": "critical", "title": "Security group opened to world",
         "finding_count": 6, "rule_source": "vpc-flow", "unique_actors": 3, "unique_resources": 6},
        {"rule_id": "ciem-sts-007", "severity": "high", "title": "Cross-account access without external ID",
         "finding_count": 5, "rule_source": "cloudtrail", "unique_actors": 2, "unique_resources": 3},
        {"rule_id": "ciem-lambda-008", "severity": "high", "title": "Lambda function modified from untrusted IP",
         "finding_count": 4, "rule_source": "cloudtrail", "unique_actors": 2, "unique_resources": 4},
        {"rule_id": "ciem-kms-005", "severity": "high", "title": "KMS key scheduled for deletion",
         "finding_count": 3, "rule_source": "cloudtrail", "unique_actors": 1, "unique_resources": 2},
        {"rule_id": "ciem-eks-010", "severity": "high", "title": "EKS cluster endpoint exposure changed",
         "finding_count": 3, "rule_source": "cloudtrail", "unique_actors": 2, "unique_resources": 2},
    ]

    # ── 4 log sources (matching real BFF contract) ────────────────────────
    log_sources = [
        {"source_type": "cloudtrail",  "source_bucket": f"s3://cloudtrail-logs-{acct0}",
         "source_region": REGIONS[3], "event_count": 284500,
         "earliest": _past_date(27), "latest": _past_date(0)},
        {"source_type": "vpc-flow",    "source_bucket": f"s3://vpc-flow-logs-{acct0}",
         "source_region": REGIONS[3], "event_count": 1250000,
         "earliest": _past_date(27), "latest": _past_date(0)},
        {"source_type": "guardduty",   "source_bucket": f"s3://guardduty-findings-{acct0}",
         "source_region": REGIONS[3], "event_count": 3420,
         "earliest": _past_date(22), "latest": _past_date(0)},
        {"source_type": "config",      "source_bucket": f"s3://aws-config-{acct0}",
         "source_region": REGIONS[3], "event_count": 48200,
         "earliest": _past_date(27), "latest": _past_date(0)},
    ]

    total_events = sum(s["event_count"] for s in log_sources)

    page_context = {
        "title": "CIEM \u2014 Log Analysis",
        "brief": "Cloud identity and entitlement management with log-based detection",
        "details": [
            "Detect privilege escalation and credential compromise via CloudTrail analysis",
            "Monitor cross-account access and lateral movement patterns",
            "Track identity risk scores and anomalous API activity",
        ],
        "tabs": [
            {"id": "overview", "label": "Overview", "count": len(top_critical)},
            {"id": "identities", "label": "Identity Risk", "count": len(identities)},
            {"id": "detections", "label": "Detection Rules", "count": len(top_rules)},
            {"id": "events", "label": "Log Sources", "count": len(log_sources)},
        ],
    }

    kpi_groups = [
        {
            "title": "Detection Summary",
            "items": [
                {"label": "Total Findings", "value": 87},
                {"label": "Rules Triggered", "value": 24},
                {"label": "Unique Actors", "value": 12},
                {"label": "Unique Resources", "value": 38},
            ],
        },
        {
            "title": "Log Coverage",
            "items": [
                {"label": "Total Events", "value": total_events},
                {"label": "Log Sources", "value": len(log_sources)},
                {"label": "L2 Findings", "value": 52},
                {"label": "L3 Findings", "value": 35},
            ],
        },
    ]

    return {
        "pageContext": page_context,
        "kpiGroups": kpi_groups,

        # Summary KPIs
        "totalFindings": 87,
        "rulesTriggered": 24,
        "uniqueActors": 12,
        "uniqueResources": 38,
        "l2Findings": 52,
        "l3Findings": 35,

        # Breakdowns — arrays of {key, count} matching real BFF
        "severityBreakdown": [
            {"severity": "critical", "count": 18},
            {"severity": "high",     "count": 27},
            {"severity": "medium",   "count": 29},
            {"severity": "low",      "count": 13},
        ],
        "engineBreakdown": [
            {"primary_engine": "ciem",   "count": 52},
            {"primary_engine": "threat", "count": 20},
            {"primary_engine": "iam",    "count": 15},
        ],
        "ruleSourceBreakdown": [
            {"rule_source": "cloudtrail", "count": 48},
            {"rule_source": "vpc-flow",   "count": 22},
            {"rule_source": "guardduty",  "count": 10},
            {"rule_source": "config",     "count": 7},
        ],
        "categoryBreakdown": [
            {"category": "privilege_escalation",  "count": 18},
            {"category": "data_exposure",         "count": 15},
            {"category": "network_security",      "count": 14},
            {"category": "credential_compromise", "count": 12},
            {"category": "persistence",           "count": 10},
            {"category": "defense_evasion",       "count": 9},
            {"category": "lateral_movement",      "count": 5},
            {"category": "exfiltration",          "count": 4},
        ],

        # Tables
        "topCritical": top_critical,
        "identities": identities,
        "topRules": top_rules,

        # Log collection
        "logSources": log_sources,
        "eventStats": {"total_events": total_events},
        "eventsBySource": [
            {"source_type": "cloudtrail", "count": 284500},
            {"source_type": "vpc-flow",   "count": 1250000},
            {"source_type": "guardduty",  "count": 3420},
            {"source_type": "config",     "count": 48200},
        ],
    }


# ── 8. Rules ────────────────────────────────────────────────────────────────

_RULE_DEFINITIONS = [
    ("aws.ec2.public-ip", "EC2 instance has public IP address", "ec2", "Detect EC2 instances with public IP assigned"),
    ("aws.ec2.imdsv1", "EC2 instance with IMDSv1 enabled", "ec2", "Ensure IMDSv2 is enforced on all instances"),
    ("aws.ec2.unrestricted-ssh", "Security group allows unrestricted SSH", "ec2", "Security groups should not allow 0.0.0.0/0 on port 22"),
    ("aws.s3.public-acl", "S3 bucket has public ACL", "s3", "S3 buckets should not allow public ACLs"),
    ("aws.s3.no-encryption", "S3 bucket without default encryption", "s3", "Enable default encryption on all S3 buckets"),
    ("aws.s3.no-versioning", "S3 bucket without versioning", "s3", "Enable versioning for data protection"),
    ("aws.s3.no-lifecycle", "S3 bucket without lifecycle policy", "s3", "Configure lifecycle rules to manage object storage"),
    ("aws.rds.public-access", "RDS instance publicly accessible", "rds", "RDS instances should not be publicly accessible"),
    ("aws.rds.no-encryption", "RDS instance without encryption at rest", "rds", "Enable encryption at rest for all RDS instances"),
    ("aws.rds.no-backup", "RDS instance without automated backups", "rds", "Enable automated backups with adequate retention"),
    ("aws.iam.no-mfa", "IAM user without MFA enabled", "iam", "All IAM users with console access must have MFA"),
    ("aws.iam.admin-access", "IAM entity with full admin access", "iam", "Avoid granting AdministratorAccess to users or roles"),
    ("aws.iam.key-rotation", "IAM access key not rotated in 90 days", "iam", "Rotate access keys every 90 days"),
    ("aws.iam.root-access-key", "Root account has active access keys", "iam", "Remove access keys from the root account"),
    ("aws.cloudtrail.disabled", "CloudTrail not enabled in region", "cloudtrail", "Enable CloudTrail in all regions"),
    ("aws.cloudtrail.no-log-validation", "CloudTrail log file validation disabled", "cloudtrail", "Enable log file integrity validation"),
    ("aws.kms.key-rotation", "KMS key rotation not enabled", "kms", "Enable automatic key rotation for KMS keys"),
    ("aws.kms.permissive-policy", "KMS key with overly permissive policy", "kms", "Restrict KMS key policies to specific principals"),
    ("aws.lambda.admin-role", "Lambda function with admin privileges", "lambda", "Apply least-privilege execution role"),
    ("aws.lambda.env-secrets", "Lambda function with secrets in env vars", "lambda", "Store secrets in Secrets Manager, not env vars"),
    ("aws.eks.public-endpoint", "EKS cluster endpoint publicly accessible", "eks", "Disable public endpoint or restrict CIDR"),
    ("aws.eks.no-audit-log", "EKS cluster without audit logging", "eks", "Enable control plane audit logging"),
    ("aws.dynamodb.no-encryption", "DynamoDB table without encryption", "dynamodb", "Enable encryption at rest for DynamoDB tables"),
    ("aws.dynamodb.no-pitr", "DynamoDB without point-in-time recovery", "dynamodb", "Enable PITR for disaster recovery"),
    ("aws.sqs.no-encryption", "SQS queue without server-side encryption", "sqs", "Enable SSE for SQS queues"),
    ("aws.sqs.cross-account", "SQS queue allows cross-account access", "sqs", "Restrict queue policy to known accounts"),
    ("aws.sns.no-encryption", "SNS topic without encryption", "sns", "Enable encryption for SNS topics"),
    ("aws.elasticache.no-encryption", "ElastiCache without encryption at rest", "elasticache", "Enable encryption at rest"),
    ("aws.redshift.public-access", "Redshift cluster publicly accessible", "redshift", "Disable public accessibility"),
    ("aws.redshift.no-encryption", "Redshift cluster without encryption", "redshift", "Enable encryption for Redshift clusters"),
]

_RULE_FRAMEWORKS = ["CIS AWS 1.5", "NIST 800-53", "ISO 27001", "PCI-DSS 4.0", "HIPAA", "SOC 2", "GDPR"]

_RULE_TEMPLATES = [
    {"id": "tmpl-resource-policy", "name": "Resource Policy Check", "description": "Template for evaluating resource-based policies", "parameters": ["service", "resource_type", "policy_field"]},
    {"id": "tmpl-encryption-check", "name": "Encryption at Rest", "description": "Template for verifying encryption configuration", "parameters": ["service", "encryption_field", "key_type"]},
    {"id": "tmpl-network-exposure", "name": "Network Exposure", "description": "Template for detecting public network exposure", "parameters": ["service", "port", "cidr_field"]},
    {"id": "tmpl-logging-enabled", "name": "Logging Enabled", "description": "Template for verifying logging configuration", "parameters": ["service", "log_type", "destination"]},
]


def mock_rules() -> dict:
    """Mock response for /api/v1/views/rules — matches real BFF /rules contract."""
    random.seed(42)

    rules = []
    for i in range(30):
        rule_id, name, service, description = _RULE_DEFINITIONS[i]
        sev = _severity_weight()
        status = "active" if random.random() > 0.1 else "inactive"
        rule_type = "built-in" if i < 26 else "custom"
        tested = random.randint(20, 200)
        passing = random.randint(int(tested * 0.3), tested)
        num_frameworks = random.randint(1, 4)
        frameworks = random.sample(_RULE_FRAMEWORKS, num_frameworks)

        rules.append({
            "rule_id": rule_id,
            "name": name,
            "description": description,
            "provider": "AWS",
            "service": service,
            "severity": sev,
            "status": status,
            "rule_type": rule_type,
            "frameworks": frameworks,
            "passing_resources": passing,
            "tested_resources": tested,
        })

    # ── Aggregate KPIs ────────────────────────────────────────────────────
    total = len(rules)
    active = sum(1 for r in rules if r["status"] == "active")
    built_in = sum(1 for r in rules if r["rule_type"] == "built-in")
    custom = total - built_in

    by_provider = {}
    by_severity = {}
    by_service = {}
    by_framework = {}
    for r in rules:
        by_provider[r["provider"]] = by_provider.get(r["provider"], 0) + 1
        by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + 1
        by_service[r["service"]] = by_service.get(r["service"], 0) + 1
        for fw in r["frameworks"]:
            by_framework[fw] = by_framework.get(fw, 0) + 1

    return {
        "pageContext": {
            "title": "Security Rules",
            "brief": "Rule catalog managing built-in and custom security checks "
                     "mapped to compliance frameworks.",
            "tabs": [
                {"id": "rules",     "label": "Rules",     "count": total},
                {"id": "templates", "label": "Templates", "count": len(_RULE_TEMPLATES)},
            ],
        },
        "kpiGroups": [
            {
                "title": "Rule Catalog",
                "items": [
                    {"label": "Total Rules", "value": total},
                    {"label": "Active",      "value": active},
                    {"label": "Built-in",    "value": built_in},
                    {"label": "Custom",      "value": custom},
                ],
            },
            {
                "title": "Coverage",
                "items": [
                    {"label": "Providers",  "value": len(by_provider)},
                    {"label": "Services",   "value": len(by_service)},
                    {"label": "Frameworks", "value": len(by_framework)},
                    {"label": "Templates",  "value": len(_RULE_TEMPLATES)},
                ],
            },
        ],
        "rules": rules,
        "kpi": {
            "totalRules": total,
            "activeRules": active,
            "builtInRules": built_in,
            "customRules": custom,
            "providers": len(by_provider),
            "byProvider": by_provider,
            "bySeverity": by_severity,
            "byService": by_service,
            "byFramework": by_framework,
        },
        "templates": _RULE_TEMPLATES,
        "statistics": {},
    }


# ── Data Security ────────────────────────────────────────────────────────────

def mock_datasec() -> dict:
    """Data security posture — catalog, classification, DLP, encryption, residency, access."""

    _OWNERS = ["data-team@example.com", "platform@example.com", "analytics@example.com"]

    _ds_names = [
        ("prod-users-db", "RDS", "us-east-1", "588989875114", "42 GB", 1_250_000, "PII", "AES-256", False),
        ("prod-orders-db", "RDS", "us-east-1", "588989875114", "128 GB", 8_400_000, "PCI", "AES-256", False),
        ("staging-analytics", "Redshift", "us-west-2", "312456789012", "500 GB", 45_000_000, "Confidential", "AES-256", False),
        ("patient-records", "RDS", "us-east-1", "588989875114", "18 GB", 320_000, "PHI", "AES-256", False),
        ("prod-logs-bucket", "S3", "us-east-1", "588989875114", "2.1 TB", None, "Internal", "SSE-S3", False),
        ("data-lake-raw", "S3", "us-west-2", "312456789012", "4.7 TB", None, "Confidential", "SSE-KMS", False),
        ("user-uploads", "S3", "eu-west-1", "588989875114", "890 GB", None, "PII", "SSE-S3", True),
        ("session-store", "DynamoDB", "us-east-1", "588989875114", "5 GB", 2_100_000, "Internal", "AES-256", False),
        ("audit-trail", "DynamoDB", "us-east-1", "588989875114", "12 GB", 18_000_000, "Confidential", "AES-256", False),
        ("dev-test-data", "RDS", "us-west-2", "198765432109", "8 GB", 450_000, "PII", "None", False),
        ("backup-archive", "S3", "us-east-1", "588989875114", "6.3 TB", None, "PHI", "SSE-KMS", False),
        ("ml-training-data", "S3", "us-west-2", "312456789012", "1.8 TB", None, "Confidential", "SSE-S3", False),
        ("reporting-warehouse", "Redshift", "us-east-1", "588989875114", "1.2 TB", 92_000_000, "PCI", "AES-256", False),
        ("config-store", "DynamoDB", "ap-south-1", "588989875114", "1 GB", 85_000, "Internal", "AES-256", False),
        ("public-assets", "S3", "us-east-1", "588989875114", "340 GB", None, "Internal", "SSE-S3", True),
    ]
    catalog = []
    for i, (name, dtype, region, acct, size, records, classif, enc, public) in enumerate(_ds_names):
        catalog.append({
            "id": f"ds-{i+1:03d}",
            "name": name,
            "type": dtype,
            "provider": "aws",
            "region": region,
            "account": acct,
            "size": size,
            "records": records,
            "classification": classif,
            "encryption": enc,
            "public_access": public,
            "owner": _OWNERS[i % len(_OWNERS)],
            "last_scanned": _past_date(7),
        })

    classifications = [
        {"name": "Email Address", "type": "PII", "count": 1_245_000, "locations": ["prod-users-db", "user-uploads"], "confidence": 0.98, "auto_classified": True},
        {"name": "Credit Card Number", "type": "PCI", "count": 328_000, "locations": ["prod-orders-db", "reporting-warehouse"], "confidence": 0.99, "auto_classified": True},
        {"name": "SSN", "type": "PII", "count": 42_000, "locations": ["patient-records", "dev-test-data"], "confidence": 0.97, "auto_classified": True},
        {"name": "Medical Record Number", "type": "PHI", "count": 320_000, "locations": ["patient-records", "backup-archive"], "confidence": 0.95, "auto_classified": True},
        {"name": "API Key", "type": "Confidential", "count": 1_850, "locations": ["data-lake-raw", "audit-trail"], "confidence": 0.92, "auto_classified": False},
        {"name": "Internal Employee ID", "type": "Internal", "count": 18_500, "locations": ["session-store", "config-store"], "confidence": 0.88, "auto_classified": True},
    ]

    dlp = [
        {"id": "dlp-001", "type": "data_exfiltration", "resource": "user-uploads", "data_type": "PII", "severity": "critical", "action": "blocked", "timestamp": _past_date(3)},
        {"id": "dlp-002", "type": "unauthorized_access", "resource": "patient-records", "data_type": "PHI", "severity": "high", "action": "alerted", "timestamp": _past_date(5)},
        {"id": "dlp-003", "type": "policy_violation", "resource": "dev-test-data", "data_type": "PII", "severity": "high", "action": "quarantined", "timestamp": _past_date(2)},
        {"id": "dlp-004", "type": "cross_account_copy", "resource": "data-lake-raw", "data_type": "Confidential", "severity": "medium", "action": "alerted", "timestamp": _past_date(7)},
        {"id": "dlp-005", "type": "unencrypted_transfer", "resource": "prod-logs-bucket", "data_type": "Internal", "severity": "medium", "action": "blocked", "timestamp": _past_date(1)},
    ]

    encryption = [
        {"resource": "prod-users-db", "type": "RDS", "rotation": "90 days", "status": "compliant"},
        {"resource": "prod-orders-db", "type": "RDS", "rotation": "90 days", "status": "compliant"},
        {"resource": "patient-records", "type": "RDS", "rotation": "90 days", "status": "compliant"},
        {"resource": "dev-test-data", "type": "RDS", "rotation": "N/A", "status": "non_compliant"},
        {"resource": "prod-logs-bucket", "type": "S3", "rotation": "N/A", "status": "compliant"},
        {"resource": "user-uploads", "type": "S3", "rotation": "N/A", "status": "at_risk"},
        {"resource": "session-store", "type": "DynamoDB", "rotation": "365 days", "status": "compliant"},
        {"resource": "staging-analytics", "type": "Redshift", "rotation": "180 days", "status": "compliant"},
    ]

    residency = [
        {"region": "us-east-1", "assets": 8, "compliance": "GDPR, SOC2, HIPAA", "status": "compliant"},
        {"region": "us-west-2", "assets": 4, "compliance": "SOC2", "status": "compliant"},
        {"region": "eu-west-1", "assets": 1, "compliance": "GDPR", "status": "at_risk"},
        {"region": "ap-south-1", "assets": 2, "compliance": "SOC2", "status": "compliant"},
    ]

    _users = ["analyst@example.com", "admin@example.com", "etl-service", "bi-reader", "data-team@example.com"]
    _actions = ["SELECT", "COPY", "EXPORT", "DESCRIBE", "UPDATE", "DELETE"]
    _locations = ["10.0.1.42", "10.0.2.18", "172.16.0.5", "198.51.100.22", "vpn-gateway"]
    access_monitoring = []
    for i in range(10):
        is_anomaly = i in (2, 7)
        access_monitoring.append({
            "timestamp": _past_date(5),
            "resource": catalog[i % len(catalog)]["name"],
            "user": _users[i % len(_users)],
            "action": _actions[i % len(_actions)],
            "location": _locations[i % len(_locations)],
            "anomaly": is_anomaly,
        })

    pii_count = sum(1 for c in catalog if c["classification"] == "PII")
    phi_count = sum(1 for c in catalog if c["classification"] == "PHI")
    enc_count = sum(1 for c in catalog if c["encryption"] != "None")
    unenc_count = len(catalog) - enc_count
    public_count = sum(1 for c in catalog if c["public_access"])
    anomaly_count = sum(1 for a in access_monitoring if a["anomaly"])

    return {
        "pageContext": {
            "title": "Data Security",
            "brief": f"{len(catalog)} data stores cataloged — {pii_count} PII, {phi_count} PHI sources",
            "details": [
                "Discovers and classifies sensitive data across cloud storage services",
                "Monitors encryption posture — SSE-S3, SSE-KMS, AES-256 at rest",
                "DLP policy enforcement with block, alert, and quarantine actions",
                "Data residency tracking to ensure compliance with sovereignty requirements",
                "Access monitoring with anomaly detection for suspicious data access patterns",
            ],
            "tabs": [
                {"id": "catalog", "label": "Data Catalog", "count": len(catalog)},
                {"id": "classifications", "label": "Classifications", "count": len(classifications)},
                {"id": "dlp", "label": "DLP Policies", "count": len(dlp)},
                {"id": "encryption", "label": "Encryption", "count": len(encryption)},
                {"id": "residency", "label": "Residency", "count": len(residency)},
                {"id": "access", "label": "Access Monitoring", "count": len(access_monitoring)},
            ],
        },
        "kpiGroups": [
            {
                "title": "Data Inventory",
                "items": [
                    {"label": "Data Stores", "value": len(catalog)},
                    {"label": "PII Sources", "value": pii_count},
                    {"label": "Encrypted", "value": enc_count},
                    {"label": "Unencrypted", "value": unenc_count},
                ],
            },
            {
                "title": "Protection",
                "items": [
                    {"label": "DLP Incidents", "value": len(dlp)},
                    {"label": "Public Access", "value": public_count},
                    {"label": "Anomalous Access", "value": anomaly_count},
                    {"label": "Residency Compliant", "value": sum(1 for r in residency if r["status"] == "compliant")},
                ],
            },
        ],
        "catalog": catalog,
        "classifications": classifications,
        "dlp": dlp,
        "encryption": encryption,
        "residency": residency,
        "accessMonitoring": access_monitoring,
    }


# ── Encryption Security ─────────────────────────────────────────────────────

def mock_encryption() -> dict:
    """Encryption posture — keys, certificates, secrets, findings."""

    page_context = {
        "title": "Encryption Security",
        "brief": "Encryption posture across KMS keys, certificates, secrets, and resource-level encryption",
        "details": [
            "Monitor KMS key rotation, certificate expiry, and secret rotation",
            "Track encryption coverage across all resource types",
            "Identify resources missing encryption at rest or in transit",
        ],
        "tabs": [],  # populated below after data is built
    }

    kpi_groups = [
        {
            "id": "posture",
            "title": "Encryption Posture",
            "kpis": [
                {"id": "posture_score", "label": "Posture Score", "value": 78, "format": "score"},
                {"id": "pct_encrypted", "label": "Encrypted", "value": 91.2, "format": "percent"},
                {"id": "total_resources", "label": "Total Resources", "value": 342, "format": "number"},
                {"id": "encrypted_resources", "label": "Encrypted Resources", "value": 312, "format": "number"},
                {"id": "unencrypted_resources", "label": "Unencrypted", "value": 30, "format": "number"},
            ],
        },
        {
            "id": "key_mgmt",
            "title": "Key Management",
            "kpis": [
                {"id": "total_keys", "label": "KMS Keys", "value": 8, "format": "number"},
                {"id": "keys_rotated", "label": "Rotation Compliant", "value": 6, "format": "number"},
                {"id": "expiring_certs", "label": "Expiring Certs (30d)", "value": 2, "format": "number"},
                {"id": "secrets_rotated", "label": "Secrets Rotated", "value": 3, "format": "number"},
            ],
        },
        {
            "id": "severity",
            "title": "Findings by Severity",
            "kpis": [
                {"id": "critical", "label": "Critical", "value": 2, "format": "number"},
                {"id": "high", "label": "High", "value": 5, "format": "number"},
                {"id": "medium", "label": "Medium", "value": 6, "format": "number"},
                {"id": "low", "label": "Low", "value": 2, "format": "number"},
            ],
        },
    ]

    kpis = [
        {"id": "posture_score", "label": "Posture Score", "value": 78, "format": "score"},
        {"id": "pct_encrypted", "label": "Encrypted", "value": 91.2, "format": "percent"},
        {"id": "total_resources", "label": "Total Resources", "value": 342, "format": "number"},
        {"id": "encrypted_resources", "label": "Encrypted Resources", "value": 312, "format": "number"},
        {"id": "unencrypted_resources", "label": "Unencrypted", "value": 30, "format": "number"},
        {"id": "total_keys", "label": "KMS Keys", "value": 8, "format": "number"},
        {"id": "keys_rotated", "label": "Rotation Compliant", "value": 6, "format": "number"},
        {"id": "expiring_certs", "label": "Expiring Certs (30d)", "value": 2, "format": "number"},
        {"id": "secrets_rotated", "label": "Secrets Rotated", "value": 3, "format": "number"},
        {"id": "critical", "label": "Critical", "value": 2, "format": "number"},
        {"id": "high", "label": "High", "value": 5, "format": "number"},
        {"id": "medium", "label": "Medium", "value": 6, "format": "number"},
        {"id": "low", "label": "Low", "value": 2, "format": "number"},
    ]

    # Resources — 20
    _res_defs = [
        ("prod-users-db", "rds", "us-east-1", "588989875114", "AES-256", True, True),
        ("prod-orders-db", "rds", "us-east-1", "588989875114", "AES-256", True, True),
        ("patient-records", "rds", "us-east-1", "588989875114", "AES-256", True, True),
        ("dev-test-db", "rds", "us-west-2", "198765432109", "None", False, False),
        ("staging-analytics", "redshift", "us-west-2", "312456789012", "AES-256", True, True),
        ("prod-logs-bucket", "s3", "us-east-1", "588989875114", "SSE-S3", True, False),
        ("data-lake-raw", "s3", "us-west-2", "312456789012", "SSE-KMS", True, True),
        ("user-uploads", "s3", "eu-west-1", "588989875114", "SSE-S3", True, False),
        ("public-assets", "s3", "us-east-1", "588989875114", "SSE-S3", True, False),
        ("backup-archive", "s3", "us-east-1", "588989875114", "SSE-KMS", True, True),
        ("session-store", "dynamodb", "us-east-1", "588989875114", "AES-256", True, True),
        ("audit-trail", "dynamodb", "us-east-1", "588989875114", "AES-256", True, True),
        ("config-store", "dynamodb", "ap-south-1", "588989875114", "AES-256", True, False),
        ("prod-cache-001", "elasticache", "us-east-1", "588989875114", "AES-256", True, True),
        ("prod-cache-002", "elasticache", "us-west-2", "312456789012", "None", False, False),
        ("order-queue", "sqs", "us-east-1", "588989875114", "SSE-KMS", True, True),
        ("notifications", "sns", "us-east-1", "588989875114", "SSE-KMS", True, True),
        ("event-bus", "sqs", "us-west-2", "312456789012", "None", False, False),
        ("reporting-warehouse", "redshift", "us-east-1", "588989875114", "AES-256", True, True),
        ("temp-storage", "s3", "us-west-2", "198765432109", "None", False, False),
    ]
    enc_resources = []
    for i, (name, svc, region, acct, alg, at_rest, in_transit) in enumerate(_res_defs):
        enc_resources.append({
            "id": f"enc-r-{i+1:03d}",
            "resource_name": name,
            "resource_type": svc,
            "region": region,
            "account_id": acct,
            "algorithm": alg,
            "encrypted_at_rest": at_rest,
            "encrypted_in_transit": in_transit,
            "kms_key_id": f"arn:aws:kms:{region}:{acct}:key/{hashlib.sha256(name.encode()).hexdigest()[:8]}" if alg not in ("None", "SSE-S3") else None,
            "last_evaluated": _past_date(5),
        })

    # KMS keys — 8
    _key_defs = [
        ("prod-data-key", "us-east-1", "588989875114", True, "Enabled", 365),
        ("prod-rds-key", "us-east-1", "588989875114", True, "Enabled", 365),
        ("backup-key", "us-east-1", "588989875114", True, "Enabled", 180),
        ("staging-key", "us-west-2", "312456789012", True, "Enabled", 365),
        ("dev-key", "us-west-2", "198765432109", False, "Enabled", None),
        ("legacy-key", "us-east-1", "588989875114", False, "PendingDeletion", None),
        ("sqs-encryption-key", "us-east-1", "588989875114", True, "Enabled", 365),
        ("redshift-key", "us-east-1", "588989875114", True, "Enabled", 180),
    ]
    keys = []
    for alias, region, acct, rotation, status, rotation_days in _key_defs:
        keys.append({
            "key_id": f"arn:aws:kms:{region}:{acct}:key/{hashlib.sha256(alias.encode()).hexdigest()[:12]}",
            "alias": alias,
            "region": region,
            "account_id": acct,
            "rotation_enabled": rotation,
            "status": status,
            "rotation_period_days": rotation_days,
            "creation_date": (now - timedelta(days=random.randint(90, 720))).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_rotated": _past_date(90) if rotation else None,
        })

    # Certificates — 6
    _cert_defs = [
        ("*.prod.example.com", "us-east-1", "588989875114", "ACM", 45, "ISSUED"),
        ("api.example.com", "us-east-1", "588989875114", "ACM", 120, "ISSUED"),
        ("admin.example.com", "eu-west-1", "588989875114", "ACM", 8, "ISSUED"),
        ("internal.staging.example.com", "us-west-2", "312456789012", "ACM", 210, "ISSUED"),
        ("legacy.example.com", "us-east-1", "588989875114", "IMPORTED", -5, "EXPIRED"),
        ("vpn.example.com", "ap-south-1", "588989875114", "ACM", 22, "ISSUED"),
    ]
    certificates = []
    for domain, region, acct, cert_type, days_to_expiry, status in _cert_defs:
        certificates.append({
            "certificate_id": f"arn:aws:acm:{region}:{acct}:certificate/{hashlib.sha256(domain.encode()).hexdigest()[:12]}",
            "domain": domain,
            "region": region,
            "account_id": acct,
            "type": cert_type,
            "status": status,
            "days_to_expiry": days_to_expiry,
            "issuer": "Amazon" if cert_type == "ACM" else "DigiCert",
            "key_algorithm": "RSA-2048",
            "auto_renewal": cert_type == "ACM",
        })

    # Secrets — 4
    secrets = [
        {"secret_id": "arn:aws:secretsmanager:us-east-1:588989875114:secret:prod/db/master", "name": "prod/db/master", "region": "us-east-1", "account_id": "588989875114", "rotation_enabled": True, "last_rotated": _past_date(30), "rotation_interval_days": 90, "status": "compliant"},
        {"secret_id": "arn:aws:secretsmanager:us-east-1:588989875114:secret:prod/api/key", "name": "prod/api/key", "region": "us-east-1", "account_id": "588989875114", "rotation_enabled": True, "last_rotated": _past_date(15), "rotation_interval_days": 60, "status": "compliant"},
        {"secret_id": "arn:aws:secretsmanager:us-west-2:312456789012:secret:staging/db/master", "name": "staging/db/master", "region": "us-west-2", "account_id": "312456789012", "rotation_enabled": True, "last_rotated": _past_date(45), "rotation_interval_days": 90, "status": "compliant"},
        {"secret_id": "arn:aws:secretsmanager:us-west-2:198765432109:secret:dev/db/password", "name": "dev/db/password", "region": "us-west-2", "account_id": "198765432109", "rotation_enabled": False, "last_rotated": None, "rotation_interval_days": None, "status": "non_compliant"},
    ]

    # Findings — 15
    _enc_finding_defs = [
        ("ENC-001", "RDS instance without encryption at rest", "rds", "critical", "dev-test-db"),
        ("ENC-002", "ElastiCache cluster without encryption", "elasticache", "critical", "prod-cache-002"),
        ("ENC-003", "KMS key rotation not enabled", "kms", "high", "dev-key"),
        ("ENC-004", "KMS key scheduled for deletion", "kms", "high", "legacy-key"),
        ("ENC-005", "S3 bucket using SSE-S3 instead of SSE-KMS", "s3", "medium", "prod-logs-bucket"),
        ("ENC-006", "Certificate expiring within 30 days", "acm", "high", "admin.example.com"),
        ("ENC-007", "Certificate expired", "acm", "high", "legacy.example.com"),
        ("ENC-008", "Secret rotation not enabled", "secretsmanager", "high", "dev/db/password"),
        ("ENC-009", "SQS queue without encryption", "sqs", "medium", "event-bus"),
        ("ENC-010", "S3 bucket without default encryption", "s3", "medium", "temp-storage"),
        ("ENC-011", "DynamoDB table using AWS-owned key", "dynamodb", "low", "config-store"),
        ("ENC-012", "S3 bucket without HTTPS-only policy", "s3", "medium", "user-uploads"),
        ("ENC-013", "Certificate not using RSA-4096", "acm", "low", "vpn.example.com"),
        ("ENC-014", "ElastiCache in-transit encryption disabled", "elasticache", "medium", "prod-cache-001"),
        ("ENC-015", "SNS topic encryption key not rotated", "sns", "medium", "notifications"),
    ]
    enc_findings = []
    for rule_id, title, svc, sev, resource in _enc_finding_defs:
        acct = random.choice(ACCOUNTS)
        region = random.choice(REGIONS)
        enc_findings.append({
            "finding_id": _make_finding_id(rule_id, resource, acct["account_id"], region),
            "rule_id": rule_id,
            "title": title,
            "resource_type": svc,
            "resource_uid": _random_arn(svc, acct["account_id"], region, resource),
            "resource_name": resource,
            "severity": sev,
            "status": "FAIL",
            "account_id": acct["account_id"],
            "region": region,
            "provider": "aws",
            "first_seen_at": _past_date(60),
            "last_seen_at": _past_date(2),
        })

    data = {
        "resources": enc_resources,
        "keys": keys,
        "certificates": certificates,
        "secrets": secrets,
        "findings": enc_findings,
    }

    page_context["tabs"] = [
        {"id": "overview", "label": "Overview", "count": len(enc_resources)},
        {"id": "keys", "label": "Keys", "count": len(keys)},
        {"id": "certificates", "label": "Certificates", "count": len(certificates)},
        {"id": "secrets", "label": "Secrets", "count": len(secrets)},
        {"id": "findings", "label": "Findings", "count": len(enc_findings)},
    ]

    return {
        "pageContext": page_context,
        "kpiGroups": kpi_groups,
        "kpis": kpis,
        "data": data,
        "overview": enc_resources,
        "findings": enc_findings,
        "keys": keys,
        "certificates": certificates,
        "secrets": secrets,
    }


# ── Network Security ─────────────────────────────────────────────────────────

def mock_network_security() -> dict:
    """Network security — findings, security groups, internet exposure, topology, WAF."""

    page_context = {
        "title": "Network Security",
        "brief": "Network posture across VPCs, security groups, NACLs, and WAF rules",
        "details": [
            "Identify overly permissive security groups and NACLs",
            "Detect internet-exposed resources and open ports",
            "Monitor WAF rule effectiveness and blocked requests",
        ],
        "tabs": [],  # populated below after data is built
    }

    kpi_groups = [
        {
            "id": "posture",
            "title": "Network Posture",
            "kpis": [
                {"id": "posture_score", "label": "Posture Score", "value": 72, "format": "score"},
                {"id": "total_vpcs", "label": "VPCs", "value": 5, "format": "number"},
                {"id": "total_sgs", "label": "Security Groups", "value": 48, "format": "number"},
                {"id": "internet_exposed", "label": "Internet Exposed", "value": 8, "format": "number"},
                {"id": "waf_rules", "label": "WAF Rules", "value": 14, "format": "number"},
            ],
        },
        {
            "id": "severity",
            "title": "Findings by Severity",
            "kpis": [
                {"id": "critical", "label": "Critical", "value": 3, "format": "number"},
                {"id": "high", "label": "High", "value": 6, "format": "number"},
                {"id": "medium", "label": "Medium", "value": 8, "format": "number"},
                {"id": "low", "label": "Low", "value": 3, "format": "number"},
            ],
        },
    ]

    # Findings — 20
    _net_finding_defs = [
        ("NET-001", "Security group allows unrestricted SSH (0.0.0.0/0:22)", "ec2", "critical"),
        ("NET-002", "Security group allows unrestricted RDP (0.0.0.0/0:3389)", "ec2", "critical"),
        ("NET-003", "Security group allows all traffic inbound (0.0.0.0/0:all)", "ec2", "critical"),
        ("NET-004", "NACL allows unrestricted inbound traffic", "vpc", "high"),
        ("NET-005", "VPC flow logs not enabled", "vpc", "high"),
        ("NET-006", "Default security group allows inbound traffic", "ec2", "high"),
        ("NET-007", "RDS instance in public subnet", "rds", "high"),
        ("NET-008", "ElastiCache cluster not in VPC", "elasticache", "high"),
        ("NET-009", "Lambda function not in VPC", "lambda", "medium"),
        ("NET-010", "ELB using HTTP instead of HTTPS", "elb", "high"),
        ("NET-011", "Security group with wide port range (0-65535)", "ec2", "medium"),
        ("NET-012", "VPC peering with unrestricted routing", "vpc", "medium"),
        ("NET-013", "NAT gateway in public subnet without EIP restriction", "vpc", "medium"),
        ("NET-014", "WAF rule set not up to date", "waf", "medium"),
        ("NET-015", "Transit gateway without route table association", "vpc", "medium"),
        ("NET-016", "Security group referenced by no instances", "ec2", "low"),
        ("NET-017", "VPC endpoint policy allows full access", "vpc", "medium"),
        ("NET-018", "DNS query logging not enabled", "route53", "low"),
        ("NET-019", "CloudFront distribution without WAF", "cloudfront", "medium"),
        ("NET-020", "Network Firewall not logging dropped packets", "vpc", "low"),
    ]
    net_findings = []
    for rule_id, title, svc, sev in _net_finding_defs:
        acct = random.choice(ACCOUNTS)
        region = random.choice(REGIONS)
        net_findings.append({
            "finding_id": _make_finding_id(rule_id, f"{svc}-resource", acct["account_id"], region),
            "rule_id": rule_id,
            "title": title,
            "resource_type": svc,
            "resource_uid": _random_arn(svc, acct["account_id"], region, f"{svc}-{rule_id.lower()}"),
            "severity": sev,
            "status": "FAIL",
            "account_id": acct["account_id"],
            "region": region,
            "provider": "aws",
            "first_seen_at": _past_date(45),
            "last_seen_at": _past_date(2),
        })

    # Security Groups — 10
    _sg_defs = [
        ("sg-0a1b2c3d4e5f00001", "prod-web-sg", "588989875114", "us-east-1", 3, 2, True, ["i-0a1b2c3d4e5f67890"]),
        ("sg-0a1b2c3d4e5f00002", "prod-db-sg", "588989875114", "us-east-1", 2, 1, False, ["i-0b2c3d4e5f678901a"]),
        ("sg-0a1b2c3d4e5f00003", "prod-cache-sg", "588989875114", "us-east-1", 2, 1, False, ["prod-cache-001"]),
        ("sg-0a1b2c3d4e5f00004", "staging-web-sg", "312456789012", "us-west-2", 4, 2, True, ["i-staging-web-01"]),
        ("sg-0a1b2c3d4e5f00005", "dev-all-traffic", "198765432109", "us-west-2", 1, 1, True, ["i-dev-01", "i-dev-02"]),
        ("sg-0a1b2c3d4e5f00006", "prod-lambda-sg", "588989875114", "us-east-1", 0, 1, False, []),
        ("sg-0a1b2c3d4e5f00007", "prod-ecs-sg", "588989875114", "us-east-1", 2, 2, False, ["ecs-task-01"]),
        ("sg-0a1b2c3d4e5f00008", "default", "588989875114", "us-east-1", 1, 1, True, []),
        ("sg-0a1b2c3d4e5f00009", "prod-eks-node-sg", "588989875114", "ap-south-1", 3, 2, False, ["i-eks-node-01", "i-eks-node-02"]),
        ("sg-0a1b2c3d4e5f00010", "bastion-sg", "588989875114", "us-east-1", 1, 1, True, ["i-bastion-01"]),
    ]
    security_groups = []
    for sg_id, name, acct, region, inbound, outbound, internet, attached in _sg_defs:
        security_groups.append({
            "group_id": sg_id,
            "name": name,
            "account_id": acct,
            "region": region,
            "inbound_rules": inbound,
            "outbound_rules": outbound,
            "internet_facing": internet,
            "attached_resources": attached,
            "vpc_id": f"vpc-{hashlib.sha256(f'{acct}{region}'.encode()).hexdigest()[:12]}",
        })

    # Internet Exposure — 8
    internet_exposure = [
        {"resource": "i-0a1b2c3d4e5f67890", "type": "ec2", "region": "us-east-1", "account_id": "588989875114", "public_ip": "54.210.123.45", "ports": [80, 443], "severity": "high"},
        {"resource": "prod-alb", "type": "elb", "region": "us-east-1", "account_id": "588989875114", "public_ip": "54.210.123.100", "ports": [80, 443], "severity": "medium"},
        {"resource": "i-staging-web-01", "type": "ec2", "region": "us-west-2", "account_id": "312456789012", "public_ip": "44.230.45.67", "ports": [22, 80, 443], "severity": "critical"},
        {"resource": "i-dev-01", "type": "ec2", "region": "us-west-2", "account_id": "198765432109", "public_ip": "44.230.89.12", "ports": [22, 80, 443, 3389], "severity": "critical"},
        {"resource": "prod-api-gw", "type": "apigateway", "region": "us-east-1", "account_id": "588989875114", "public_ip": "N/A", "ports": [443], "severity": "low"},
        {"resource": "cdn.example.com", "type": "cloudfront", "region": "global", "account_id": "588989875114", "public_ip": "N/A", "ports": [443], "severity": "low"},
        {"resource": "dev-test-db", "type": "rds", "region": "us-west-2", "account_id": "198765432109", "public_ip": "44.230.102.55", "ports": [5432], "severity": "critical"},
        {"resource": "staging-redshift", "type": "redshift", "region": "us-west-2", "account_id": "312456789012", "public_ip": "44.230.78.33", "ports": [5439], "severity": "high"},
    ]

    # Topology — 5 VPCs
    topology = [
        {"vpc_id": "vpc-prod-east-1", "name": "prod-vpc", "region": "us-east-1", "account_id": "588989875114", "cidr": "10.0.0.0/16", "subnets": 6, "route_tables": 3, "nat_gateways": 2, "peering_connections": 1},
        {"vpc_id": "vpc-prod-west-2", "name": "prod-dr-vpc", "region": "us-west-2", "account_id": "588989875114", "cidr": "10.1.0.0/16", "subnets": 4, "route_tables": 2, "nat_gateways": 1, "peering_connections": 1},
        {"vpc_id": "vpc-staging", "name": "staging-vpc", "region": "us-west-2", "account_id": "312456789012", "cidr": "10.2.0.0/16", "subnets": 4, "route_tables": 2, "nat_gateways": 1, "peering_connections": 0},
        {"vpc_id": "vpc-dev", "name": "dev-vpc", "region": "us-west-2", "account_id": "198765432109", "cidr": "10.3.0.0/16", "subnets": 2, "route_tables": 1, "nat_gateways": 0, "peering_connections": 0},
        {"vpc_id": "vpc-eks", "name": "eks-vpc", "region": "ap-south-1", "account_id": "588989875114", "cidr": "10.4.0.0/16", "subnets": 6, "route_tables": 3, "nat_gateways": 2, "peering_connections": 1},
    ]

    # WAF — 3
    waf = [
        {"web_acl_id": "waf-prod-api", "name": "prod-api-waf", "region": "us-east-1", "account_id": "588989875114", "rules": 8, "blocked_requests_24h": 1245, "allowed_requests_24h": 892_340, "associated_resources": ["prod-alb"]},
        {"web_acl_id": "waf-prod-cdn", "name": "prod-cdn-waf", "region": "global", "account_id": "588989875114", "rules": 4, "blocked_requests_24h": 678, "allowed_requests_24h": 2_450_000, "associated_resources": ["cdn.example.com"]},
        {"web_acl_id": "waf-staging", "name": "staging-waf", "region": "us-west-2", "account_id": "312456789012", "rules": 2, "blocked_requests_24h": 45, "allowed_requests_24h": 12_300, "associated_resources": ["staging-alb"]},
    ]

    page_context["tabs"] = [
        {"id": "overview", "label": "Overview", "count": len(net_findings)},
        {"id": "findings", "label": "Findings", "count": len(net_findings)},
        {"id": "security_groups", "label": "Security Groups", "count": len(security_groups)},
        {"id": "internet_exposure", "label": "Internet Exposure", "count": len(internet_exposure)},
        {"id": "topology", "label": "Topology", "count": len(topology)},
        {"id": "waf", "label": "WAF", "count": len(waf)},
    ]

    return {
        "pageContext": page_context,
        "kpiGroups": kpi_groups,
        "data": {
            "findings": net_findings,
            "security_groups": security_groups,
            "internet_exposure": internet_exposure,
            "topology": topology,
            "waf": waf,
        },
    }


# ── Database Security ────────────────────────────────────────────────────────

def mock_database_security() -> dict:
    """Database security — posture, findings, domain scores."""

    page_context = {
        "title": "Database Security",
        "brief": "Security posture across RDS, DynamoDB, Redshift, and ElastiCache databases",
        "details": [
            "Evaluate access control, encryption, audit logging, backup, and network security",
            "Track publicly accessible databases and unencrypted instances",
            "Monitor database-specific compliance findings",
        ],
        "tabs": [],  # populated below after data is built
    }

    kpi_groups = [
        {
            "id": "posture",
            "title": "Database Posture",
            "kpis": [
                {"id": "posture_score", "label": "Posture Score", "value": 74, "format": "score"},
                {"id": "total_databases", "label": "Total Databases", "value": 10, "format": "number"},
                {"id": "publicly_accessible", "label": "Publicly Accessible", "value": 2, "format": "number"},
                {"id": "unencrypted", "label": "Unencrypted", "value": 1, "format": "number"},
            ],
        },
        {
            "id": "severity",
            "title": "Findings by Severity",
            "kpis": [
                {"id": "critical", "label": "Critical", "value": 2, "format": "number"},
                {"id": "high", "label": "High", "value": 4, "format": "number"},
                {"id": "medium", "label": "Medium", "value": 6, "format": "number"},
                {"id": "low", "label": "Low", "value": 3, "format": "number"},
            ],
        },
    ]

    # Databases — 10
    _db_defs = [
        ("prod-users-db", "rds", "PostgreSQL", "15.4", 88, False, True, "us-east-1", "588989875114"),
        ("prod-orders-db", "rds", "PostgreSQL", "15.4", 85, False, True, "us-east-1", "588989875114"),
        ("patient-records", "rds", "MySQL", "8.0.35", 82, False, True, "us-east-1", "588989875114"),
        ("dev-test-db", "rds", "PostgreSQL", "14.9", 35, True, False, "us-west-2", "198765432109"),
        ("staging-analytics", "redshift", "Redshift", "1.0", 78, False, True, "us-west-2", "312456789012"),
        ("reporting-warehouse", "redshift", "Redshift", "1.0", 80, False, True, "us-east-1", "588989875114"),
        ("session-store", "dynamodb", "DynamoDB", "N/A", 90, False, True, "us-east-1", "588989875114"),
        ("audit-trail", "dynamodb", "DynamoDB", "N/A", 92, False, True, "us-east-1", "588989875114"),
        ("config-store", "dynamodb", "DynamoDB", "N/A", 75, False, True, "ap-south-1", "588989875114"),
        ("prod-cache-001", "elasticache", "Redis", "7.0", 70, False, True, "us-east-1", "588989875114"),
    ]
    databases = []
    for name, db_service, engine, version, score, public, encrypted, region, acct in _db_defs:
        databases.append({
            "name": name,
            "db_service": db_service,
            "engine": engine,
            "version": version,
            "posture_score": score,
            "publicly_accessible": public,
            "encrypted": encrypted,
            "region": region,
            "account_id": acct,
            "resource_uid": _random_arn(db_service, acct, region, name),
            "multi_az": score > 75,
            "backup_retention_days": 7 if score > 60 else 0,
            "last_evaluated": _past_date(3),
        })

    # Findings — 15
    _db_finding_defs = [
        ("DBSEC-001", "RDS instance publicly accessible", "rds", "critical", "dev-test-db"),
        ("DBSEC-002", "RDS instance without encryption at rest", "rds", "critical", "dev-test-db"),
        ("DBSEC-003", "RDS instance without automated backups", "rds", "high", "dev-test-db"),
        ("DBSEC-004", "RDS instance with default master username", "rds", "high", "dev-test-db"),
        ("DBSEC-005", "Redshift cluster audit logging disabled", "redshift", "high", "staging-analytics"),
        ("DBSEC-006", "DynamoDB table without point-in-time recovery", "dynamodb", "medium", "config-store"),
        ("DBSEC-007", "ElastiCache cluster without encryption in transit", "elasticache", "medium", "prod-cache-001"),
        ("DBSEC-008", "RDS instance not using latest engine version", "rds", "medium", "patient-records"),
        ("DBSEC-009", "Redshift parameter group with require_ssl disabled", "redshift", "high", "staging-analytics"),
        ("DBSEC-010", "RDS enhanced monitoring not enabled", "rds", "medium", "prod-users-db"),
        ("DBSEC-011", "DynamoDB table using default encryption", "dynamodb", "low", "session-store"),
        ("DBSEC-012", "RDS instance not in Multi-AZ", "rds", "medium", "dev-test-db"),
        ("DBSEC-013", "ElastiCache automatic failover disabled", "elasticache", "medium", "prod-cache-001"),
        ("DBSEC-014", "RDS deletion protection not enabled", "rds", "low", "dev-test-db"),
        ("DBSEC-015", "DynamoDB table without server-side encryption with CMK", "dynamodb", "low", "audit-trail"),
    ]
    db_findings = []
    for rule_id, title, svc, sev, resource in _db_finding_defs:
        acct = random.choice(ACCOUNTS)
        region = random.choice(REGIONS)
        db_findings.append({
            "finding_id": _make_finding_id(rule_id, resource, acct["account_id"], region),
            "rule_id": rule_id,
            "title": title,
            "resource_type": svc,
            "resource_uid": _random_arn(svc, acct["account_id"], region, resource),
            "resource_name": resource,
            "severity": sev,
            "status": "FAIL",
            "account_id": acct["account_id"],
            "region": region,
            "provider": "aws",
            "first_seen_at": _past_date(60),
            "last_seen_at": _past_date(2),
        })

    domain_scores = {
        "access_control": 78,
        "encryption": 82,
        "audit_logging": 65,
        "backup_recovery": 72,
        "network_security": 70,
    }

    page_context["tabs"] = [
        {"id": "overview", "label": "Overview", "count": len(databases)},
        {"id": "databases", "label": "Databases", "count": len(databases)},
        {"id": "findings", "label": "Findings", "count": len(db_findings)},
    ]

    return {
        "pageContext": page_context,
        "kpiGroups": kpi_groups,
        "data": {
            "databases": databases,
            "findings": db_findings,
            "domain_scores": domain_scores,
        },
    }


# ── Container Security ───────────────────────────────────────────────────────

def mock_container_security() -> dict:
    """Container security — EKS/ECS clusters, findings, domain scores."""

    page_context = {
        "title": "Container Security",
        "brief": "Security posture for EKS and ECS clusters, workloads, and images",
        "details": [
            "Cluster-level security configuration and RBAC analysis",
            "Workload and image vulnerability scanning",
            "Network exposure and pod security policy evaluation",
        ],
        "tabs": [],  # populated below after data is built
    }

    kpi_groups = [
        {
            "id": "posture",
            "title": "Container Posture",
            "kpis": [
                {"id": "posture_score", "label": "Posture Score", "value": 68, "format": "score"},
                {"id": "total_clusters", "label": "Clusters", "value": 5, "format": "number"},
                {"id": "total_workloads", "label": "Workloads", "value": 42, "format": "number"},
                {"id": "vulnerable_images", "label": "Vulnerable Images", "value": 8, "format": "number"},
            ],
        },
        {
            "id": "severity",
            "title": "Findings by Severity",
            "kpis": [
                {"id": "critical", "label": "Critical", "value": 2, "format": "number"},
                {"id": "high", "label": "High", "value": 3, "format": "number"},
                {"id": "medium", "label": "Medium", "value": 5, "format": "number"},
                {"id": "low", "label": "Low", "value": 2, "format": "number"},
            ],
        },
    ]

    clusters = [
        {
            "cluster_name": "prod-eks-cluster", "type": "EKS", "version": "1.29",
            "region": "ap-south-1", "account_id": "588989875114",
            "node_count": 6, "pod_count": 38, "namespace_count": 5,
            "posture_score": 75, "endpoint_public": True,
            "logging_enabled": True, "secrets_encryption": True,
            "resource_uid": "arn:aws:eks:ap-south-1:588989875114:cluster/prod-eks-cluster",
        },
        {
            "cluster_name": "staging-eks-cluster", "type": "EKS", "version": "1.28",
            "region": "us-west-2", "account_id": "312456789012",
            "node_count": 3, "pod_count": 18, "namespace_count": 3,
            "posture_score": 62, "endpoint_public": True,
            "logging_enabled": False, "secrets_encryption": True,
            "resource_uid": "arn:aws:eks:us-west-2:312456789012:cluster/staging-eks-cluster",
        },
        {
            "cluster_name": "dev-eks-cluster", "type": "EKS", "version": "1.27",
            "region": "us-west-2", "account_id": "198765432109",
            "node_count": 2, "pod_count": 12, "namespace_count": 2,
            "posture_score": 45, "endpoint_public": True,
            "logging_enabled": False, "secrets_encryption": False,
            "resource_uid": "arn:aws:eks:us-west-2:198765432109:cluster/dev-eks-cluster",
        },
        {
            "cluster_name": "prod-ecs-cluster", "type": "ECS", "version": "N/A",
            "region": "us-east-1", "account_id": "588989875114",
            "node_count": 4, "pod_count": 22, "namespace_count": 1,
            "posture_score": 80, "endpoint_public": False,
            "logging_enabled": True, "secrets_encryption": True,
            "resource_uid": "arn:aws:ecs:us-east-1:588989875114:cluster/prod-ecs-cluster",
        },
        {
            "cluster_name": "batch-ecs-cluster", "type": "ECS", "version": "N/A",
            "region": "us-east-1", "account_id": "588989875114",
            "node_count": 2, "pod_count": 8, "namespace_count": 1,
            "posture_score": 72, "endpoint_public": False,
            "logging_enabled": True, "secrets_encryption": False,
            "resource_uid": "arn:aws:ecs:us-east-1:588989875114:cluster/batch-ecs-cluster",
        },
    ]

    # Findings — 12
    _ctr_finding_defs = [
        ("CTR-001", "EKS cluster endpoint publicly accessible", "eks", "critical", "dev-eks-cluster"),
        ("CTR-002", "EKS cluster without secrets encryption", "eks", "critical", "dev-eks-cluster"),
        ("CTR-003", "EKS cluster audit logging disabled", "eks", "high", "staging-eks-cluster"),
        ("CTR-004", "ECS task definition with host network mode", "ecs", "high", "prod-ecs-cluster"),
        ("CTR-005", "Container running as root", "eks", "high", "prod-eks-cluster"),
        ("CTR-006", "Pod with hostPath volume mount", "eks", "medium", "staging-eks-cluster"),
        ("CTR-007", "Container image with known CVEs", "ecs", "medium", "prod-ecs-cluster"),
        ("CTR-008", "EKS node group using outdated AMI", "eks", "medium", "prod-eks-cluster"),
        ("CTR-009", "Privileged container detected", "eks", "medium", "dev-eks-cluster"),
        ("CTR-010", "ECS task role with excessive permissions", "ecs", "medium", "batch-ecs-cluster"),
        ("CTR-011", "Pod security policy not enforced", "eks", "low", "staging-eks-cluster"),
        ("CTR-012", "Container without resource limits", "eks", "low", "dev-eks-cluster"),
    ]
    ctr_findings = []
    for rule_id, title, svc, sev, resource in _ctr_finding_defs:
        acct = random.choice(ACCOUNTS)
        region = random.choice(REGIONS)
        ctr_findings.append({
            "finding_id": _make_finding_id(rule_id, resource, acct["account_id"], region),
            "rule_id": rule_id,
            "title": title,
            "resource_type": svc,
            "resource_uid": _random_arn(svc, acct["account_id"], region, f"cluster/{resource}"),
            "resource_name": resource,
            "severity": sev,
            "status": "FAIL",
            "account_id": acct["account_id"],
            "region": region,
            "provider": "aws",
            "first_seen_at": _past_date(30),
            "last_seen_at": _past_date(2),
        })

    domain_scores = {
        "cluster_security": 72,
        "workload_security": 65,
        "image_security": 58,
        "network_exposure": 75,
        "rbac_access": 70,
    }

    page_context["tabs"] = [
        {"id": "overview", "label": "Overview", "count": len(clusters)},
        {"id": "clusters", "label": "Clusters", "count": len(clusters)},
        {"id": "findings", "label": "Findings", "count": len(ctr_findings)},
    ]

    return {
        "pageContext": page_context,
        "kpiGroups": kpi_groups,
        "data": {
            "clusters": clusters,
            "findings": ctr_findings,
            "domain_scores": domain_scores,
        },
    }


# ── AI Security ──────────────────────────────────────────────────────────────

def mock_ai_security() -> dict:
    """AI/ML security — findings, inventory, shadow AI detection."""

    page_context = {
        "title": "AI Security",
        "brief": "Security posture for AI/ML services — SageMaker, Bedrock, Comprehend, and more",
        "details": [
            "Identify misconfigured ML training jobs and endpoints",
            "Detect shadow AI usage across accounts",
            "Monitor model access controls and data pipeline security",
        ],
        "tabs": [],  # populated below after data is built
    }

    kpi_groups = [
        {
            "id": "posture",
            "title": "AI Security Posture",
            "kpis": [
                {"id": "posture_score", "label": "Posture Score", "value": 62, "format": "score"},
                {"id": "total_ml_resources", "label": "ML Resources", "value": 6, "format": "number"},
                {"id": "shadow_ai_detected", "label": "Shadow AI", "value": 3, "format": "number"},
                {"id": "total_findings", "label": "Total Findings", "value": 10, "format": "number"},
            ],
        },
        {
            "id": "severity",
            "title": "Findings by Severity",
            "kpis": [
                {"id": "critical", "label": "Critical", "value": 1, "format": "number"},
                {"id": "high", "label": "High", "value": 3, "format": "number"},
                {"id": "medium", "label": "Medium", "value": 4, "format": "number"},
                {"id": "low", "label": "Low", "value": 2, "format": "number"},
            ],
        },
    ]

    _ai_finding_defs = [
        ("AI-001", "SageMaker notebook instance with root access", "sagemaker", "critical", "prod-ml-notebook"),
        ("AI-002", "SageMaker endpoint without encryption", "sagemaker", "high", "fraud-model-endpoint"),
        ("AI-003", "Bedrock model invocation logging disabled", "bedrock", "high", "claude-integration"),
        ("AI-004", "SageMaker training job with internet access", "sagemaker", "high", "training-job-v3"),
        ("AI-005", "Comprehend entity recognizer with public training data", "comprehend", "medium", "pii-detector"),
        ("AI-006", "SageMaker model artifact stored in unencrypted S3", "sagemaker", "medium", "model-artifacts"),
        ("AI-007", "Bedrock guardrail not configured", "bedrock", "medium", "chatbot-integration"),
        ("AI-008", "SageMaker endpoint auto-scaling not configured", "sagemaker", "medium", "recommendation-endpoint"),
        ("AI-009", "Rekognition collection without access policy", "rekognition", "low", "face-collection"),
        ("AI-010", "SageMaker notebook lifecycle config missing", "sagemaker", "low", "dev-notebook"),
    ]
    ai_findings = []
    for rule_id, title, svc, sev, resource in _ai_finding_defs:
        acct = random.choice(ACCOUNTS)
        region = random.choice(REGIONS)
        ai_findings.append({
            "finding_id": _make_finding_id(rule_id, resource, acct["account_id"], region),
            "rule_id": rule_id,
            "title": title,
            "resource_type": svc,
            "resource_uid": _random_arn(svc, acct["account_id"], region, resource),
            "resource_name": resource,
            "severity": sev,
            "status": "FAIL",
            "account_id": acct["account_id"],
            "region": region,
            "provider": "aws",
            "first_seen_at": _past_date(30),
            "last_seen_at": _past_date(2),
        })

    inventory = [
        {"resource_name": "prod-ml-notebook", "resource_type": "sagemaker", "service": "SageMaker Notebook", "region": "us-east-1", "account_id": "588989875114", "status": "InService", "instance_type": "ml.t3.xlarge", "resource_uid": "arn:aws:sagemaker:us-east-1:588989875114:notebook-instance/prod-ml-notebook"},
        {"resource_name": "fraud-model-endpoint", "resource_type": "sagemaker", "service": "SageMaker Endpoint", "region": "us-east-1", "account_id": "588989875114", "status": "InService", "instance_type": "ml.m5.large", "resource_uid": "arn:aws:sagemaker:us-east-1:588989875114:endpoint/fraud-model-endpoint"},
        {"resource_name": "recommendation-endpoint", "resource_type": "sagemaker", "service": "SageMaker Endpoint", "region": "us-west-2", "account_id": "312456789012", "status": "InService", "instance_type": "ml.m5.xlarge", "resource_uid": "arn:aws:sagemaker:us-west-2:312456789012:endpoint/recommendation-endpoint"},
        {"resource_name": "claude-integration", "resource_type": "bedrock", "service": "Bedrock Model", "region": "us-east-1", "account_id": "588989875114", "status": "Active", "instance_type": "N/A", "resource_uid": "arn:aws:bedrock:us-east-1:588989875114:model/claude-integration"},
        {"resource_name": "pii-detector", "resource_type": "comprehend", "service": "Comprehend Recognizer", "region": "us-east-1", "account_id": "588989875114", "status": "TRAINED", "instance_type": "N/A", "resource_uid": "arn:aws:comprehend:us-east-1:588989875114:entity-recognizer/pii-detector"},
        {"resource_name": "face-collection", "resource_type": "rekognition", "service": "Rekognition Collection", "region": "us-east-1", "account_id": "588989875114", "status": "Active", "instance_type": "N/A", "resource_uid": "arn:aws:rekognition:us-east-1:588989875114:collection/face-collection"},
    ]

    shadow_ai = [
        {"resource_name": "dev-notebook", "resource_type": "sagemaker", "region": "us-west-2", "account_id": "198765432109", "detected_at": _past_date(14), "owner": "unknown", "risk": "high", "reason": "Unapproved SageMaker notebook in dev account"},
        {"resource_name": "chatbot-integration", "resource_type": "bedrock", "region": "us-east-1", "account_id": "312456789012", "detected_at": _past_date(7), "owner": "unknown", "risk": "medium", "reason": "Bedrock model invocation from staging account without approval"},
        {"resource_name": "text-analysis-lambda", "resource_type": "comprehend", "region": "eu-west-1", "account_id": "198765432109", "detected_at": _past_date(3), "owner": "unknown", "risk": "medium", "reason": "Comprehend API calls from unapproved Lambda function"},
    ]

    page_context["tabs"] = [
        {"id": "overview", "label": "Overview", "count": len(ai_findings)},
        {"id": "findings", "label": "Findings", "count": len(ai_findings)},
        {"id": "inventory", "label": "ML Resources", "count": len(inventory)},
        {"id": "shadow_ai", "label": "Shadow AI", "count": len(shadow_ai)},
    ]

    return {
        "pageContext": page_context,
        "kpiGroups": kpi_groups,
        "findings": ai_findings,
        "inventory": inventory,
        "shadowAI": shadow_ai,
        "modules": [],
    }


# ── Risk ─────────────────────────────────────────────────────────────────────

def mock_risk() -> dict:
    """Risk management — FAIR scenarios, risk register, mitigation roadmap, trends."""

    risk_score = 67

    risk_categories = [
        {"category": "Data Exposure", "score": 82, "findings": 18, "trend": "increasing"},
        {"category": "Identity & Access", "score": 74, "findings": 14, "trend": "stable"},
        {"category": "Network Security", "score": 65, "findings": 11, "trend": "decreasing"},
        {"category": "Compliance", "score": 58, "findings": 8, "trend": "stable"},
        {"category": "Infrastructure", "score": 52, "findings": 6, "trend": "decreasing"},
    ]

    scenarios = [
        {"scenario_name": "Customer PII breach via public S3", "threat_category": "data_exposure", "probability": 0.35, "expected_loss": 2_400_000, "worst_case_loss": 12_000_000, "risk_rating": "critical", "threat_event_frequency": 4.2, "vulnerability": 0.78, "loss_magnitude": 8_500_000},
        {"scenario_name": "Credential theft via exposed IAM keys", "threat_category": "credential_theft", "probability": 0.28, "expected_loss": 1_800_000, "worst_case_loss": 8_500_000, "risk_rating": "critical", "threat_event_frequency": 6.1, "vulnerability": 0.62, "loss_magnitude": 5_200_000},
        {"scenario_name": "Privilege escalation to admin", "threat_category": "privilege_escalation", "probability": 0.22, "expected_loss": 950_000, "worst_case_loss": 5_000_000, "risk_rating": "high", "threat_event_frequency": 3.5, "vulnerability": 0.55, "loss_magnitude": 3_800_000},
        {"scenario_name": "Lateral movement via security group misconfiguration", "threat_category": "lateral_movement", "probability": 0.18, "expected_loss": 720_000, "worst_case_loss": 3_200_000, "risk_rating": "high", "threat_event_frequency": 2.8, "vulnerability": 0.48, "loss_magnitude": 2_100_000},
        {"scenario_name": "Ransomware on unpatched EC2 instances", "threat_category": "resource_hijacking", "probability": 0.15, "expected_loss": 1_200_000, "worst_case_loss": 6_000_000, "risk_rating": "high", "threat_event_frequency": 1.9, "vulnerability": 0.42, "loss_magnitude": 4_500_000},
        {"scenario_name": "Compliance violation — PHI data residency", "threat_category": "data_exposure", "probability": 0.12, "expected_loss": 500_000, "worst_case_loss": 2_500_000, "risk_rating": "medium", "threat_event_frequency": 1.2, "vulnerability": 0.35, "loss_magnitude": 1_800_000},
        {"scenario_name": "DDoS on public-facing services", "threat_category": "resource_hijacking", "probability": 0.25, "expected_loss": 180_000, "worst_case_loss": 800_000, "risk_rating": "medium", "threat_event_frequency": 8.5, "vulnerability": 0.30, "loss_magnitude": 450_000},
        {"scenario_name": "Shadow IT resource provisioning", "threat_category": "defense_evasion", "probability": 0.30, "expected_loss": 120_000, "worst_case_loss": 600_000, "risk_rating": "medium", "threat_event_frequency": 12.0, "vulnerability": 0.25, "loss_magnitude": 280_000},
    ]

    risk_register = [
        {"id": "RISK-001", "title": "Unencrypted customer data in S3", "category": "Data Protection", "inherent": 92, "residual": 45, "owner": "alice@example.com", "status": "mitigating"},
        {"id": "RISK-002", "title": "Overly permissive IAM policies", "category": "Identity & Access", "inherent": 85, "residual": 52, "owner": "bob@example.com", "status": "mitigating"},
        {"id": "RISK-003", "title": "Public-facing databases without WAF", "category": "Network Security", "inherent": 88, "residual": 38, "owner": "carol@example.com", "status": "accepted"},
        {"id": "RISK-004", "title": "Missing CloudTrail in 3 regions", "category": "Logging & Monitoring", "inherent": 72, "residual": 25, "owner": "david@example.com", "status": "resolved"},
        {"id": "RISK-005", "title": "Expired SSL certificates on staging", "category": "Encryption", "inherent": 65, "residual": 60, "owner": "alice@example.com", "status": "open"},
        {"id": "RISK-006", "title": "Container images with critical CVEs", "category": "Compute", "inherent": 78, "residual": 48, "owner": "bob@example.com", "status": "mitigating"},
    ]

    mitigation_roadmap = [
        {"action": "Enable SSE-KMS on all S3 buckets", "current_risk": 92, "target_risk": 30, "cost": "$2,400/yr", "priority": "P1", "owner": "alice@example.com", "due_date": "2026-04-15"},
        {"action": "Implement least-privilege IAM policy review", "current_risk": 85, "target_risk": 35, "cost": "$0 (internal)", "priority": "P1", "owner": "bob@example.com", "due_date": "2026-04-30"},
        {"action": "Deploy WAF on all public endpoints", "current_risk": 88, "target_risk": 25, "cost": "$8,500/yr", "priority": "P2", "owner": "carol@example.com", "due_date": "2026-05-15"},
        {"action": "Rotate all IAM access keys > 90 days", "current_risk": 72, "target_risk": 20, "cost": "$0 (automation)", "priority": "P1", "owner": "david@example.com", "due_date": "2026-04-10"},
        {"action": "Upgrade container base images and scan pipeline", "current_risk": 78, "target_risk": 30, "cost": "$1,200/yr", "priority": "P2", "owner": "bob@example.com", "due_date": "2026-05-30"},
    ]

    trend_data = []
    base_score = 78
    for i in range(12):
        month_dt = now - timedelta(days=(11 - i) * 30)
        score = base_score - (11 - i) * 1.2 + random.uniform(-2, 2)
        trend_data.append({
            "month": month_dt.strftime("%Y-%m"),
            "risk_score": round(max(40, min(100, score)), 1),
            "findings": random.randint(25, 65),
            "mitigated": random.randint(5, 20),
        })

    kpi = {
        "overall_risk_score": risk_score,
        "critical_risks": 2,
        "high_risks": 3,
        "medium_risks": 4,
        "low_risks": 2,
        "risks_mitigated_30d": 5,
        "total_expected_loss": sum(s["expected_loss"] for s in scenarios),
        "risk_reduction_pct": 18.5,
    }

    total_expected_loss = sum(s["expected_loss"] for s in scenarios)

    return {
        "pageContext": {
            "title": "Risk Management",
            "brief": f"Risk score: {risk_score}/100 — {len(scenarios)} FAIR scenarios, ${total_expected_loss:,.0f} expected loss",
            "details": [
                "FAIR-based quantitative risk analysis with annualized loss expectancy",
                "Risk register tracking with owner assignment and review schedules",
                "Mitigation roadmap with cost-benefit analysis and target risk reduction",
                "12-month risk score trend showing improvement trajectory",
                "Risk categories mapped to threat scenarios and financial impact",
            ],
            "tabs": [
                {"id": "overview", "label": "Overview"},
                {"id": "scenarios", "label": "FAIR Scenarios", "count": len(scenarios)},
                {"id": "register", "label": "Risk Register", "count": len(risk_register)},
                {"id": "roadmap", "label": "Mitigation Roadmap", "count": len(mitigation_roadmap)},
                {"id": "trend", "label": "Trend", "count": len(trend_data)},
            ],
        },
        "kpiGroups": [
            {
                "title": "Risk Posture",
                "items": [
                    {"label": "Risk Score", "value": risk_score, "suffix": "/100"},
                    {"label": "Total Expected Loss", "value": f"${total_expected_loss:,.0f}"},
                    {"label": "Critical Risks", "value": kpi["critical_risks"]},
                    {"label": "High Risks", "value": kpi["high_risks"]},
                ],
            },
            {
                "title": "Mitigation",
                "items": [
                    {"label": "Mitigated (30d)", "value": kpi["risks_mitigated_30d"]},
                    {"label": "Roadmap Items", "value": len(mitigation_roadmap)},
                    {"label": "Categories", "value": len(risk_categories)},
                    {"label": "Risk Reduction", "value": kpi["risk_reduction_pct"], "suffix": "%"},
                ],
            },
        ],
        "riskScore": risk_score,
        "riskCategories": risk_categories,
        "scenarios": scenarios,
        "riskRegister": risk_register,
        "mitigationRoadmap": mitigation_roadmap,
        "trendData": trend_data,
        "kpi": kpi,
    }


# ── Scans ────────────────────────────────────────────────────────────────────

def mock_scans() -> dict:
    """Scan history and scheduling."""

    _scan_types = ["Full", "Discovery", "Compliance", "Threat", "IAM"]
    _triggered_by = ["scheduled", "manual", "api", "on-demand"]
    _statuses = ["completed", "completed", "completed", "completed", "running", "failed"]

    scans = []
    for i in range(15):
        acct = ACCOUNTS[i % len(ACCOUNTS)]
        acct_id = acct["account_id"]
        acct_name = acct["account_name"]
        scan_type = _scan_types[i % len(_scan_types)]
        status = _statuses[i % len(_statuses)]
        started = now - timedelta(hours=i * 8 + random.randint(0, 4))
        duration_min = random.randint(8, 55)
        completed = started + timedelta(minutes=duration_min) if status != "running" else None
        resources = random.randint(120, 850)
        total_findings = random.randint(5, 45)
        crit = random.randint(0, 3) if total_findings > 10 else 0
        high = random.randint(1, 8) if total_findings > 5 else random.randint(0, 2)

        scans.append({
            "scan_id": "scan-" + hashlib.sha256(f"{i}-{acct_id}".encode()).hexdigest()[:12],
            "scan_name": f"{scan_type} scan - {acct_name}",
            "scan_type": scan_type,
            "provider": acct["provider"],
            "account_id": acct["account_id"],
            "account_name": acct["account_name"],
            "status": status,
            "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "completed_at": completed.strftime("%Y-%m-%dT%H:%M:%SZ") if completed else None,
            "duration": f"{duration_min}m" if status != "running" else None,
            "resources_scanned": resources if status != "running" else None,
            "total_findings": total_findings if status == "completed" else None,
            "critical_findings": crit if status == "completed" else None,
            "high_findings": high if status == "completed" else None,
            "triggered_by": _triggered_by[i % len(_triggered_by)],
        })

    scheduled = [
        {"id": "sched-001", "name": "Daily Full Scan — Prod", "scan_type": "Full", "provider": "aws", "account_id": "588989875114", "account_name": "prod-account", "schedule": "0 2 * * *", "next_run": (now + timedelta(hours=random.randint(1, 23))).strftime("%Y-%m-%dT%H:%M:%SZ"), "enabled": True, "last_run_status": "completed"},
        {"id": "sched-002", "name": "Weekly Compliance — All Accounts", "scan_type": "Compliance", "provider": "aws", "account_id": "*", "account_name": "All Accounts", "schedule": "0 3 * * 1", "next_run": (now + timedelta(days=random.randint(1, 6))).strftime("%Y-%m-%dT%H:%M:%SZ"), "enabled": True, "last_run_status": "completed"},
        {"id": "sched-003", "name": "Nightly Threat Scan — Staging", "scan_type": "Threat", "provider": "aws", "account_id": "312456789012", "account_name": "staging-account", "schedule": "0 1 * * *", "next_run": (now + timedelta(hours=random.randint(1, 23))).strftime("%Y-%m-%dT%H:%M:%SZ"), "enabled": True, "last_run_status": "completed"},
    ]

    kpi_groups = [
        {
            "id": "scan_overview",
            "title": "Scan Overview",
            "kpis": [
                {"id": "total_scans", "label": "Total Scans", "value": len(scans), "format": "number"},
                {"id": "completed", "label": "Completed", "value": len([s for s in scans if s["status"] == "completed"]), "format": "number"},
                {"id": "running", "label": "Running", "value": len([s for s in scans if s["status"] == "running"]), "format": "number"},
                {"id": "failed", "label": "Failed", "value": len([s for s in scans if s["status"] == "failed"]), "format": "number"},
                {"id": "scheduled", "label": "Scheduled", "value": len(scheduled), "format": "number"},
            ],
        },
    ]

    completed_count = len([s for s in scans if s["status"] == "completed"])
    running_count = len([s for s in scans if s["status"] == "running"])
    failed_count = len([s for s in scans if s["status"] == "failed"])

    return {
        "pageContext": {
            "title": "Scan Management",
            "brief": f"{len(scans)} scans — {completed_count} completed, {running_count} running, {failed_count} failed",
            "details": [
                "View scan history with status, duration, and findings count",
                "Monitor running scans and engine completion progress",
                "Manage scheduled scans — enable/disable, modify cron expressions",
                "Trigger ad-hoc scans for specific accounts or scan types",
                "Review failed scans with error details for troubleshooting",
            ],
            "tabs": [
                {"id": "history", "label": "Scan History", "count": len(scans)},
                {"id": "scheduled", "label": "Scheduled", "count": len(scheduled)},
            ],
        },
        "scans": scans,
        "scheduled": scheduled,
        "kpiGroups": kpi_groups,
    }
