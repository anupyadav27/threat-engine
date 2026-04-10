"""Standardized page context and filter schema definitions.

Every BFF page response includes:
  - pageContext: title, brief description, expandable details, tabs
  - filterSchema: Wiz-style structured query filter definitions

Filter operators per field type:
  - string:  is, is_not, contains, not_contains, starts_with
  - enum:    is, is_not, in, not_in
  - number:  eq, neq, gt, gte, lt, lte
  - date:    before, after, between, last_n_days
  - boolean: is
"""

from typing import Any, Dict, List, Optional


# ── Filter field types ───────────────────────────────────────────────────────

def _enum_field(key: str, label: str, values: List[str], **kwargs) -> Dict:
    return {
        "key": key,
        "label": label,
        "type": "enum",
        "operators": ["is", "is_not", "in", "not_in"],
        "values": values,
        **kwargs,
    }


def _string_field(key: str, label: str, **kwargs) -> Dict:
    return {
        "key": key,
        "label": label,
        "type": "string",
        "operators": ["is", "is_not", "contains", "not_contains", "starts_with"],
        **kwargs,
    }


def _number_field(key: str, label: str, **kwargs) -> Dict:
    return {
        "key": key,
        "label": label,
        "type": "number",
        "operators": ["eq", "neq", "gt", "gte", "lt", "lte"],
        **kwargs,
    }


def _date_field(key: str, label: str, **kwargs) -> Dict:
    return {
        "key": key,
        "label": label,
        "type": "date",
        "operators": ["before", "after", "between", "last_n_days"],
        **kwargs,
    }


def _bool_field(key: str, label: str, **kwargs) -> Dict:
    return {
        "key": key,
        "label": label,
        "type": "boolean",
        "operators": ["is"],
        "values": [True, False],
        **kwargs,
    }


# ── Common filter fields (reusable across pages) ────────────────────────────

SEVERITY_VALUES = ["critical", "high", "medium", "low", "info"]
STATUS_VALUES = ["PASS", "FAIL"]
PROVIDER_VALUES = ["aws", "azure", "gcp", "oci", "alicloud", "ibm"]

COMMON_FILTERS = [
    _enum_field("severity", "Severity", SEVERITY_VALUES),
    _enum_field("status", "Status", STATUS_VALUES),
    _enum_field("provider", "Cloud Provider", PROVIDER_VALUES),
    _string_field("account_id", "Account"),
    _string_field("region", "Region"),
    _string_field("resource_uid", "Resource ARN"),
]


# ── Page context definitions ─────────────────────────────────────────────────

def iam_page_context(summary: Dict[str, Any]) -> Dict:
    total = summary.get("total_findings", 0)
    by_sev = summary.get("by_severity", {})
    critical = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)

    return {
        "title": "IAM Security",
        "brief": f"{total} findings — {critical} critical, {high} high severity",
        "details": [
            "Evaluates IAM posture across users, roles, policies, and access keys",
            "Checks for overprivileged identities, unused credentials, and missing MFA",
            "Maps findings to CIS Benchmark IAM controls and NIST 800-53 AC family",
            "Rotate access keys every 90 days and enforce least-privilege policies",
            "Review role trust policies for cross-account access regularly",
        ],
        "tabs": [],  # populated dynamically below
    }


def iam_filter_schema(modules: List[str]) -> List[Dict]:
    return [
        _enum_field("severity", "Severity", SEVERITY_VALUES),
        _enum_field("status", "Status", STATUS_VALUES),
        _string_field("rule_id", "Rule ID"),
        _enum_field("type", "Identity Type", [
            "IAM User", "IAM Role", "IAM Policy", "IAM Group",
            "Instance Profile", "Service Account",
        ]),
        _enum_field("iam_modules", "Module", modules or [
            "role_management", "access_control", "least_privilege",
            "policy_analysis", "password_policy",
        ]),
        _string_field("username", "Identity Name"),
        _string_field("account_id", "Account"),
        _string_field("region", "Region"),
        _string_field("resource_uid", "Resource ARN"),
        _number_field("risk_score", "Risk Score"),
        _number_field("findings_count", "Findings Count"),
    ]


def compliance_page_context(summary: Dict[str, Any]) -> Dict:
    return {
        "title": "Compliance",
        "brief": "Framework compliance posture across all monitored accounts",
        "details": [
            "Evaluates resources against 13+ compliance frameworks (CIS, NIST, ISO 27001, PCI-DSS, HIPAA, GDPR, SOC 2)",
            "Maps check findings to specific framework controls",
            "Track compliance score trends across scan cycles",
            "Export compliance reports for auditors in PDF/CSV format",
            "Review failing controls sorted by severity and affected resource count",
        ],
        "tabs": [],
    }


def compliance_filter_schema() -> List[Dict]:
    return [
        _enum_field("severity", "Severity", SEVERITY_VALUES),
        _enum_field("status", "Status", STATUS_VALUES),
        _string_field("framework_id", "Framework"),
        _string_field("control_id", "Control ID"),
        _string_field("rule_id", "Rule ID"),
        _string_field("resource_type", "Resource Type"),
        _string_field("resource_uid", "Resource ARN"),
        _string_field("account_id", "Account"),
        _string_field("region", "Region"),
    ]


def inventory_page_context(summary: Dict[str, Any]) -> Dict:
    total = summary.get("total_assets") or summary.get("total", 0)
    return {
        "title": "Inventory",
        "brief": f"{total} cloud assets across all accounts and regions",
        "details": [
            "Normalized view of all cloud resources across providers",
            "Tracks asset lifecycle — first seen, last seen, configuration drift",
            "Relationship mapping between resources (VPC, subnet, security group)",
            "Architecture diagram view for visual infrastructure overview",
            "Filter by provider, service, region, or resource type",
        ],
        "tabs": [],
    }


def inventory_filter_schema() -> List[Dict]:
    return [
        _string_field("name", "Name"),
        _string_field("resource_type", "Resource Type"),
        _enum_field("provider", "Cloud Provider", PROVIDER_VALUES),
        _string_field("account_id", "Account"),
        _string_field("region", "Region"),
        _string_field("resource_uid", "Resource ARN"),
        _number_field("risk_score", "Risk Score"),
        _date_field("first_seen_at", "First Seen"),
        _date_field("last_seen_at", "Last Seen"),
    ]


def threats_page_context(summary: Dict[str, Any]) -> Dict:
    total = summary.get("total", 0)
    return {
        "title": "Threat Detection",
        "brief": f"{total} threats detected with MITRE ATT&CK mapping",
        "details": [
            "Detects threats using rule-based analysis mapped to MITRE ATT&CK framework",
            "Risk scoring (0-100) based on severity, blast radius, and exploitability",
            "Toxic combination detection — multiple findings that compound into higher risk",
            "Attack path visualization from initial access to impact",
            "Threat timeline shows detection history across scan cycles",
        ],
        "tabs": [],
    }


def threats_filter_schema() -> List[Dict]:
    return [
        _enum_field("severity", "Severity", SEVERITY_VALUES),
        _string_field("rule_id", "Rule ID"),
        _string_field("mitre_technique", "MITRE Technique"),
        _string_field("mitre_tactic", "MITRE Tactic"),
        _string_field("resource_type", "Resource Type"),
        _string_field("resource_uid", "Resource ARN"),
        _string_field("account_id", "Account"),
        _string_field("region", "Region"),
        _number_field("risk_score", "Risk Score"),
    ]


def misconfig_page_context(summary: Dict[str, Any]) -> Dict:
    total = summary.get("total_findings", 0)
    return {
        "title": "Misconfigurations",
        "brief": f"{total} configuration findings across cloud resources",
        "details": [
            "Evaluates cloud resources against security best practice rules",
            "PASS/FAIL assessment for each rule-resource combination",
            "Severity-based prioritization — fix critical findings first",
            "Rule descriptions include remediation steps and framework mappings",
            "Group by service to identify the most misconfigured areas",
        ],
        "tabs": [],
    }


def misconfig_filter_schema() -> List[Dict]:
    return [
        _enum_field("severity", "Severity", SEVERITY_VALUES),
        _enum_field("status", "Status", STATUS_VALUES),
        _string_field("rule_id", "Rule ID"),
        _string_field("service", "Service"),
        _string_field("resource_type", "Resource Type"),
        _string_field("resource_uid", "Resource ARN"),
        _string_field("account_id", "Account"),
        _string_field("region", "Region"),
    ]


def datasec_page_context(summary: Dict[str, Any]) -> Dict:
    return {
        "title": "Data Security",
        "brief": "Data classification, encryption, and exposure analysis",
        "details": [
            "Scans data stores (S3, RDS, DynamoDB, EBS) for sensitive data patterns",
            "Classifies data as PII, PHI, financial, credentials, or public",
            "Checks encryption status — at rest and in transit",
            "Identifies publicly accessible data stores",
            "Data residency mapping for GDPR and sovereignty compliance",
        ],
        "tabs": [],
    }


def datasec_filter_schema() -> List[Dict]:
    return [
        _enum_field("severity", "Severity", SEVERITY_VALUES),
        _string_field("resource_type", "Resource Type"),
        _string_field("data_classification", "Classification"),
        _string_field("resource_uid", "Resource ARN"),
        _string_field("account_id", "Account"),
        _string_field("region", "Region"),
        _bool_field("public_access", "Publicly Accessible"),
        _string_field("encryption", "Encryption Status"),
    ]


def encryption_page_context(summary: Dict[str, Any]) -> Dict:
    return {
        "title": "Encryption Security",
        "brief": "Encryption posture, key management, and certificate lifecycle",
        "details": [
            "Monitors encryption status across all cloud resources (EBS, S3, RDS, DynamoDB)",
            "Tracks KMS key usage, rotation policies, and key lifecycle",
            "Certificate inventory with expiration monitoring and renewal alerts",
            "Identifies unencrypted resources and missing encryption-at-rest/in-transit",
            "Maps findings to CIS Benchmark encryption controls and compliance frameworks",
        ],
        "tabs": [],
    }


def encryption_filter_schema() -> List[Dict]:
    return [
        _enum_field("severity", "Severity", SEVERITY_VALUES),
        _enum_field("encryption_status", "Encryption Status", [
            "encrypted", "unencrypted", "partial",
        ]),
        _enum_field("key_type", "Key Type", [
            "AWS_MANAGED", "CUSTOMER_MANAGED", "AWS_OWNED",
        ]),
        _enum_field("encryption_domain", "Encryption Domain", [
            "at_rest", "in_transit", "key_management", "certificate",
        ]),
        _enum_field("provider", "Cloud Provider", PROVIDER_VALUES),
        _string_field("account_id", "Account"),
        _string_field("region", "Region"),
    ]


def database_security_page_context(summary: Dict[str, Any]) -> Dict:
    return {
        "title": "Database Security",
        "brief": "Database posture, access control, encryption, and audit logging",
        "details": [
            "Monitors security posture across all managed database services (RDS, Aurora, DynamoDB, Redshift, ElastiCache)",
            "Evaluates access control: IAM authentication, public accessibility, security groups",
            "Checks encryption at rest and in transit for all database instances",
            "Audits logging configuration: audit logs, slow query logs, general logs",
            "Verifies backup and recovery: automated backups, retention periods, multi-AZ deployments",
            "Maps findings to CIS Benchmark database controls and compliance frameworks",
        ],
        "tabs": [],
    }


def database_security_filter_schema() -> List[Dict]:
    return [
        _enum_field("severity", "Severity", SEVERITY_VALUES),
        _enum_field("status", "Status", STATUS_VALUES),
        _enum_field("security_domain", "Security Domain", [
            "access_control", "encryption", "audit_logging",
            "backup_recovery", "network_security", "configuration",
        ]),
        _string_field("db_service", "DB Service"),
        _string_field("db_engine", "DB Engine"),
        _enum_field("provider", "Cloud Provider", PROVIDER_VALUES),
        _string_field("account_id", "Account"),
        _string_field("region", "Region"),
    ]


def network_security_page_context(summary: Dict[str, Any]) -> Dict:
    return {
        "title": "Network Security",
        "brief": "Network posture, segmentation, exposure, and firewall analysis",
        "details": [
            "Evaluates VPC segmentation, peering, and Transit Gateway configurations (L1)",
            "Checks route tables, internet gateways, and NAT gateway reachability (L2)",
            "Audits Network ACLs for stateless firewall misconfigurations (L3)",
            "Analyzes Security Group rules for overly permissive access (L4)",
            "Inspects Load Balancer TLS configuration and HTTP listener security (L5)",
            "Verifies WAF and Shield protection for internet-facing resources (L6)",
            "Reviews VPC Flow Logs for anomalous traffic patterns (L7)",
            "Identifies internet-exposed resources across security groups and load balancers",
        ],
        "tabs": [],
    }


def network_security_filter_schema() -> List[Dict]:
    return [
        _enum_field("severity", "Severity", SEVERITY_VALUES),
        _enum_field("status", "Status", STATUS_VALUES),
        _enum_field("module", "Module", [
            "network_isolation", "network_reachability", "network_acl",
            "security_group_rules", "load_balancer_security", "waf_protection",
            "internet_exposure", "network_monitoring",
        ]),
        _string_field("resource_type", "Resource Type"),
        _enum_field("provider", "Cloud Provider", PROVIDER_VALUES),
        _string_field("account_id", "Account"),
        _string_field("region", "Region"),
    ]


def risk_page_context(summary: Dict[str, Any]) -> Dict:
    score = summary.get("risk_score", 0)
    level = summary.get("risk_level", "unknown")
    return {
        "title": "Risk Quantification",
        "brief": f"Financial risk exposure score: {score}/100 ({level})",
        "details": [
            "FAIR model — converts security findings into dollar-denominated exposure estimates",
            "Aggregates findings from all engines: IAM, DataSec, Network, Threat, Compliance",
            "Per-record breach cost by industry (IBM 2024): healthcare $10.93, finance $6.08, tech $4.88",
            "Regulatory fine estimation: GDPR (4% revenue), HIPAA ($1.9M cap), PCI-DSS, CCPA, SOX",
            "Risk scenarios classified by exposure: Critical (>$10M), High (>$1M), Medium (>$100K)",
        ],
        "tabs": [],
    }


def scans_page_context() -> Dict:
    return {
        "title": "Scan Management",
        "brief": "Monitor and manage security scan operations",
        "details": [
            "View scan history with per-engine breakdown",
            "Track scan duration, status, and finding counts",
            "Trigger on-demand scans for specific accounts",
            "Configure scheduled scans via onboarding",
            "Pipeline: Discovery → Check + Inventory → Threat → Compliance/IAM/DataSec",
        ],
        "tabs": [],
    }


def rules_page_context() -> Dict:
    return {
        "title": "Rules",
        "brief": "Security rule catalog and management",
        "details": [
            "Define clear rule names and descriptions for auditors",
            "Map rules to specific controls in compliance frameworks",
            "Test rules against known compliant and non-compliant resources",
            "Version control all custom rules in Git repositories",
            "Review and update rules quarterly for new AWS/Azure/GCP features",
            "Document rule logic and rationale for future maintainers",
        ],
        "tabs": [],
    }


def rules_filter_schema() -> List[Dict]:
    return [
        _enum_field("severity", "Severity", SEVERITY_VALUES),
        _string_field("rule_id", "Rule ID"),
        _string_field("service", "Service"),
        _enum_field("provider", "Cloud Provider", PROVIDER_VALUES),
        _string_field("framework", "Framework"),
        _bool_field("enabled", "Enabled"),
    ]


def container_security_page_context(summary: Dict[str, Any]) -> Dict:
    return {
        "title": "Container Security",
        "brief": "Container posture, cluster security, image scanning, and RBAC analysis",
        "details": [
            "Monitors security posture across all container services (EKS, ECS, ECR, Fargate)",
            "Evaluates cluster security: API server access, control plane logging, node isolation",
            "Checks workload security: pod security standards, resource limits, privilege escalation",
            "Scans container images for vulnerabilities, outdated base images, and secrets",
            "Audits network exposure: public endpoints, service mesh, ingress configurations",
            "Verifies RBAC policies: overprivileged service accounts, cluster-admin bindings",
            "Runtime audit: container runtime anomalies, suspicious process execution",
        ],
        "tabs": [],
    }


def container_security_filter_schema() -> List[Dict]:
    return [
        _enum_field("severity", "Severity", SEVERITY_VALUES),
        _enum_field("status", "Status", STATUS_VALUES),
        _enum_field("security_domain", "Security Domain", [
            "cluster_security", "workload_security", "image_security",
            "network_exposure", "rbac_access", "runtime_audit",
        ]),
        _enum_field("container_service", "Container Service", [
            "eks", "ecs", "ecr", "fargate", "lambda",
        ]),
        _string_field("cluster_name", "Cluster Name"),
        _enum_field("provider", "Cloud Provider", PROVIDER_VALUES),
        _string_field("account_id", "Account"),
        _string_field("region", "Region"),
    ]


def ai_security_page_context(summary: Dict[str, Any]) -> Dict:
    total = summary.get("total_findings", 0)
    ml_resources = summary.get("total_ml_resources", 0)
    by_sev = summary.get("by_severity", {})
    critical = by_sev.get("critical", summary.get("critical_findings", 0))

    return {
        "title": "AI Security Posture",
        "brief": f"{total} findings across {ml_resources} AI/ML resources — {critical} critical",
        "details": [
            "Evaluates security posture of AI/ML services (SageMaker, Bedrock, Comprehend, Rekognition)",
            "Model security: training data integrity, model card compliance, artifact encryption",
            "Endpoint security: VPC isolation, encryption in transit, authentication controls",
            "Prompt security: guardrails configuration, content filtering, injection protection",
            "Data pipeline: training data encryption, lineage tracking, access controls",
            "AI governance: model versioning, audit logging, bias detection",
            "Shadow AI detection: unauthorized AI service usage across accounts",
        ],
        "tabs": [],
    }


def ai_security_filter_schema(modules: Optional[List[str]] = None) -> List[Dict]:
    return [
        _enum_field("severity", "Severity", SEVERITY_VALUES),
        _enum_field("status", "Status", STATUS_VALUES),
        _string_field("rule_id", "Rule ID"),
        _enum_field("module", "Module", modules or [
            "model_security", "endpoint_security", "prompt_security",
            "data_pipeline", "ai_governance", "access_control",
        ]),
        _string_field("resource_type", "Resource Type"),
        _enum_field("provider", "Cloud Provider", PROVIDER_VALUES),
        _string_field("account_id", "Account"),
        _string_field("region", "Region"),
        _number_field("risk_score", "Risk Score"),
        _bool_field("public", "Publicly Accessible"),
    ]
