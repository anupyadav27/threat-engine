"""
Attack Path Engine — Orca-Style Step-by-Step Path Explainer.

Generates a structured, human-readable narrative for each attack path.
Output mirrors the Orca "Security Graph" path explanation format:

  {
    "title":        "Internet-exposed EC2 instance can access sensitive S3 bucket",
    "severity":     "critical",
    "vector_type":  "T3",
    "confidence":   "likely",
    "summary":      "An attacker with access to the internet can exploit the exposed
                     EC2 instance, use its attached IAM role, and read data from the
                     PII-classified S3 bucket.",
    "steps": [
      {
        "step":            1,
        "uid":             "arn:aws:ec2:...:instance/i-12345",
        "resource_type":   "ec2.instance",
        "label":           "Internet Entry Point",
        "action":          "Exploit public-facing EC2 instance",
        "mitre_technique": "T1190 — Exploit Public-Facing Application",
        "mitre_tactic":    "Initial Access",
        "risk_signals":    ["Public IP: 54.12.x.x", "SSH port 22 open to 0.0.0.0/0"],
        "relation_to_next": "has_role →",
      },
      ...
    ],
    "impact": "Attacker can read, download, or exfiltrate data from a PII-classified S3 bucket.",
    "mitigations": [
      "Remove public IP from EC2 instance i-12345 or place it behind an ALB.",
      "Restrict IAM role s3-reader to least-privilege S3 GetObject on specific prefixes.",
      "Enable S3 Block Public Access and apply a bucket policy denying public reads.",
    ]
  }

Security notes:
  - No DB queries — works from posture_lookup and findings_lookup dicts.
  - All data came from tenant-scoped queries in run_scan.py — no cross-tenant leakage.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .attack_vector import AttackVector

logger = logging.getLogger("attack-path.path_explainer")


# ---------------------------------------------------------------------------
# Resource type → friendly display name
# ---------------------------------------------------------------------------

_TYPE_LABELS: Dict[str, str] = {
    # ── AWS Compute ──────────────────────────────────────────────────────────
    "ec2.instance":           "EC2 Instance",
    "lambda.function":        "Lambda Function",
    "lambda.resource":        "Lambda Function",
    "ecs.cluster":            "ECS Cluster",
    "ecs.service":            "ECS Service",
    "eks.cluster":            "EKS Cluster",
    # ── AWS Storage / Data ───────────────────────────────────────────────────
    "s3.bucket":              "S3 Bucket",
    "s3.resource":            "S3 Bucket",
    "rds.instance":           "RDS Database",
    "rds.db-instance":        "RDS Database",
    "rds.cluster":            "RDS Cluster",
    "rds.db-cluster":         "RDS Cluster",
    "dynamodb.table":         "DynamoDB Table",
    "dynamodb.resource":      "DynamoDB Table",
    "redshift.cluster":       "Redshift Cluster",
    "elasticache.cluster":    "ElastiCache Cluster",
    "opensearch.domain":      "OpenSearch Domain",
    "efs.file-system":        "EFS File System",
    "ec2.volume":             "EBS Volume",
    # ── AWS IAM / Identity ──────────────────────────────────────────────────
    "iam.role":               "IAM Role",
    "iam.user":               "IAM User",
    "iam.group":              "IAM Group",
    "iam.policy":             "IAM Policy",
    "iam.instance-profile":   "IAM Instance Profile",
    # ── AWS Security / Secrets ──────────────────────────────────────────────
    "kms.key":                "KMS Key",
    "secretsmanager.secret":  "Secrets Manager Secret",
    "ssm.parameter":          "SSM Parameter",
    # ── AWS Network ─────────────────────────────────────────────────────────
    "ec2.security-group":     "Security Group",
    "ec2.vpc":                "VPC",
    "vpc.vpc":                "VPC",
    "ec2.subnet":             "Subnet",
    "vpc.subnet":             "Subnet",
    "ec2.network-interface":  "Network Interface",
    "ec2.internet-gateway":   "Internet Gateway",
    "vpc.internet-gateway":   "Internet Gateway",
    "vpc.nat-gateway":        "NAT Gateway",
    "alb":                    "Application Load Balancer",
    "nlb":                    "Network Load Balancer",
    "elb":                    "Classic Load Balancer",
    "elasticloadbalancingv2.loadbalancer": "Load Balancer",
    # ── AWS API / Frontend ──────────────────────────────────────────────────
    "apigateway.restapi":     "API Gateway (REST)",
    "apigateway.httpapi":     "API Gateway (HTTP)",
    "cloudfront.distribution": "CloudFront Distribution",
    # ── AWS Queues / Messaging ──────────────────────────────────────────────
    "sns.topic":              "SNS Topic",
    "sqs.queue":              "SQS Queue",
    # ── AWS Container / ECR ─────────────────────────────────────────────────
    "ecr.repository":         "ECR Repository",
    # ── Azure ────────────────────────────────────────────────────────────────
    "azure.virtual_machine":  "Azure Virtual Machine",
    "azure.vm":               "Azure Virtual Machine",
    "azure.blob_container":   "Azure Blob Container",
    "blob.container":         "Azure Blob Container",
    "azure.storage_account":  "Azure Storage Account",
    "azure.sql_database":     "Azure SQL Database",
    "azure.key_vault":        "Azure Key Vault",
    "azure.aks_cluster":      "AKS Cluster",
    "azure.managed_identity": "Azure Managed Identity",
    "azure.function_app":     "Azure Function App",
    # ── GCP ──────────────────────────────────────────────────────────────────
    "gcp.gcs_bucket":         "GCS Bucket",
    "gcs.bucket":             "GCS Bucket",
    "gcp.compute_instance":   "GCE Instance",
    "gce.instance":           "GCE Instance",
    "gcp.gke_cluster":        "GKE Cluster",
    "gcp.iam_service_account": "GCP Service Account",
    "gcp.cloud_function":     "Cloud Function",
    "gcp.kms_crypto_key":     "GCP KMS Key",
    # ── OCI ──────────────────────────────────────────────────────────────────
    "oci.object_storage_bucket": "OCI Object Storage",
    "oci.object_storage":     "OCI Object Storage",
    "oci.compute_instance":   "OCI Compute Instance",
    "oci.autonomous_database": "OCI Autonomous Database",
    "oci.vault":              "OCI Vault",
    # ── Kubernetes ───────────────────────────────────────────────────────────
    "k8s.pod":                "Kubernetes Pod",
    "k8s.deployment":         "Kubernetes Deployment",
    "k8s.serviceaccount":     "Kubernetes Service Account",
    "k8s.secret":             "Kubernetes Secret",
    "k8s.ingress":            "Kubernetes Ingress",
    "k8s.clusterrole":        "Kubernetes ClusterRole",
}


def _friendly_type(resource_type: str) -> str:
    rt = (resource_type or "").lower()
    return _TYPE_LABELS.get(rt) or rt.replace(".", " ").replace("_", " ").title()


# ---------------------------------------------------------------------------
# Risk signal extraction per hop
# ---------------------------------------------------------------------------

def _hop_risk_signals(
    uid: str,
    resource_type: str,
    posture: Any,
    findings: Dict[str, Any],
) -> List[str]:
    """Collect human-readable risk signals for one path node."""
    signals: List[str] = []

    if posture:
        if getattr(posture, "is_internet_exposed", False):
            signals.append("Publicly accessible from the internet")
        if not getattr(posture, "waf_protected", True):
            signals.append("No WAF protection")
        if not getattr(posture, "mfa_required", True):
            signals.append("MFA not enforced")
        enc = getattr(posture, "encryption_type", None) or ""
        if enc.lower() in ("none", ""):
            signals.append("Data not encrypted at rest")
        if getattr(posture, "has_active_cdr_actor", False):
            signals.append("Active CDR threat actor detected")
        dc = getattr(posture, "data_classification", None) or ""
        if dc in ("pii", "financial", "credentials"):
            signals.append(f"Data classification: {dc.upper()}")
        br = getattr(posture, "blast_radius_count", 0)
        if br > 10:
            signals.append(f"Blast radius: {br} downstream resources affected")

    # Findings signals
    for m in findings.get("misconfigs", [])[:2]:
        title = m.get("title") or m.get("rule_id") or ""
        sev = m.get("severity") or ""
        if title:
            signals.append(f"Misconfiguration ({sev}): {title[:80]}")

    for cve in findings.get("cves", [])[:2]:
        cve_id = cve.get("rule_id") or "CVE"
        epss = cve.get("epss_score")
        epss_str = f", EPSS {epss:.2f}" if epss else ""
        signals.append(f"Vulnerability: {cve_id}{epss_str}")

    for det in findings.get("threat_detections", [])[:1]:
        tech = det.get("mitre_technique_id") or ""
        tac = det.get("mitre_tactic") or ""
        if tech:
            signals.append(f"CDR detection: {tech} ({tac})")

    return signals[:5]  # cap at 5 signals per hop


# ---------------------------------------------------------------------------
# Mitigation generation per hop
# ---------------------------------------------------------------------------

_MITIGATION_BY_SIGNAL: Dict[str, str] = {
    "publicly accessible":   "Restrict public access — place resource behind a load balancer or VPC, remove public IP.",
    "no waf":                "Add WAF protection on the public-facing resource to block common attack patterns.",
    "mfa not enforced":      "Enforce MFA on all IAM users and roles accessing this resource.",
    "not encrypted":         "Enable encryption at rest using KMS-managed keys.",
    "active cdr":            "Investigate the active CDR threat actor — isolate resource and rotate credentials.",
    "pii":                   "Apply fine-grained IAM policies limiting PII data access to specific principals.",
    "financial":             "Restrict financial data access with SCPs and resource-based policies.",
    "credentials":           "Rotate exposed credentials immediately and apply least-privilege IAM policies.",
    "blast radius":          "Segment the resource to reduce the blast radius — use VPC endpoints and resource policies.",
    "misconfiguration":      "Remediate the identified misconfiguration and rerun the compliance scan.",
    "vulnerability":         "Patch the identified CVE — update the runtime or base image.",
    "cdr detection":         "Isolate the affected resource and run an incident response playbook.",
}


def _hop_mitigations(signals: List[str]) -> List[str]:
    mitigations: List[str] = []
    seen: set = set()
    for signal in signals:
        signal_lower = signal.lower()
        for keyword, mitigation in _MITIGATION_BY_SIGNAL.items():
            if keyword in signal_lower and mitigation not in seen:
                seen.add(mitigation)
                mitigations.append(mitigation)
    return mitigations


# ---------------------------------------------------------------------------
# Path title generation
# ---------------------------------------------------------------------------

def _build_title(
    entry_type: str,
    entry_resource_type: str,
    crown_type: str,
    crown_resource_type: str,
    severity: str,
) -> str:
    """Build a concise Orca-style attack path title."""
    entry_label = _friendly_type(entry_resource_type) if entry_resource_type else entry_type.capitalize()
    crown_label = _friendly_type(crown_resource_type) if crown_resource_type else crown_type.replace("_", " ").title()

    verb = "can access"
    if crown_type in ("data", "data_warehouse"):
        verb = "can read sensitive data from"
    elif crown_type == "secrets":
        verb = "can access secrets in"
    elif crown_type == "encryption_control":
        verb = "can compromise encryption key in"
    elif crown_type == "identity":
        verb = "can escalate privileges via"

    return f"Internet-exposed {entry_label} {verb} {crown_label}"


# ---------------------------------------------------------------------------
# Summary sentence
# ---------------------------------------------------------------------------

def _build_summary(
    path_length: int,
    vector_type: str,
    confidence: str,
    entry_label: str,
    crown_label: str,
    crown_type: str,
) -> str:
    vectors = {"T1": "a single misconfiguration", "T2": "a two-hop pivot", "T3": "a multi-hop kill chain"}
    conf_phrases = {
        "confirmed":   "CDR has confirmed active exploitation activity along this path.",
        "likely":      "High-EPSS CVEs or active CDR actors indicate elevated real-world risk.",
        "speculative": "This path is based on topology analysis — no active exploitation detected.",
    }
    return (
        f"An attacker can exploit {vectors.get(vector_type, 'this path')} starting from "
        f"the {entry_label} and reach the {crown_label} "
        f"({crown_type.replace('_', ' ')}) in {path_length} step(s). "
        f"{conf_phrases.get(confidence, '')}"
    )


# ---------------------------------------------------------------------------
# Step action labelling (from edge type)
# ---------------------------------------------------------------------------

_EDGE_ACTION: Dict[str, str] = {
    # ── Exposure / Reachability ──────────────────────────────────────────────
    "exposed_via":           "Exploit internet exposure via",
    "exposes":               "Enter through internet-exposed",
    "reachable_from":        "Reach resource through open network path",
    "internet_connected":    "Exploit internet-exposed",
    # ── Data access ─────────────────────────────────────────────────────────
    "accesses":              "Access data or API of",
    "reads":                 "Read data from",
    "writes":                "Write or modify data in",
    "stores":                "Read/write stored data in",
    "stores_data_in":        "Exfiltrate data stored in",
    # ── IAM / Identity (original) ───────────────────────────────────────────
    "has_role":              "Assume IAM role attached to",
    "can_assume":            "Assume role of",
    "assumes":               "Assume identity of",
    "uses":                  "Use credentials from",
    "member_of":             "Gain privileges of group",
    "depends_on":            "Exploit dependency on",
    # ── IAM / Identity (per-engine writers) ─────────────────────────────────
    "can_access":            "Access resource via IAM permission",
    "grants_access_to":      "Gain resource access through policy grant from",
    "grants_decrypt_to":     "Decrypt and exfiltrate data via KMS grant from",
    "has_policy":            "Escalate privileges through attached policy on",
    "linked_to":             "Pivot through linked identity via",
    # ── Infrastructure / Attachment ─────────────────────────────────────────
    "attached_to":           "Access data on attached volume",
    "mounted_by":            "Read filesystem data from mounted volume in",
    "contains":              "Reach resource inside",
    "executes_on":           "Execute code on",
    "mounts":                "Escape container via mounted volume in",
    "runs_on":               "Execute workload on",
    "worker_node_of":        "Control workloads running on cluster",
    # ── Network topology (per-engine writers) ───────────────────────────────
    "routes_to":             "Route traffic to",
    "has_endpoint":          "Reach service through exposed endpoint",
    "connected_via":         "Traverse network connection to",
    "peered_with":           "Cross VPC boundary via peering to",
    "peered_with_external":  "Reach external network via cross-account peering to",
    "resolves_to":           "Follow DNS resolution to",
    "connects_to":           "Connect directly to",
    "in_vpc":                "Move within VPC containing",
    "hosted_in":             "Access via host subnet containing",
    # ── Attack path categories ───────────────────────────────────────────────
    "lateral_movement":      "Move laterally to",
    "privilege_escalation":  "Escalate privileges to",
    "data_access":           "Access data in",
    "data_flow":             "Exfiltrate data through",
    "exposure":              "Exploit exposed",
    "execution":             "Execute on",
    # ── Encryption / Audit ──────────────────────────────────────────────────
    "encrypted_by":          "Compromise encryption key protecting",
}


def _edge_action(edge_type: str, target_label: str) -> str:
    action = _EDGE_ACTION.get(edge_type.lower(), "Access")
    return f"{action} {target_label}"


# ---------------------------------------------------------------------------
# Edge context decoration
# ---------------------------------------------------------------------------
# Explains WHY a specific relationship traversal is dangerous, using source
# and target posture together. Distinct from risk_signals (which describe the
# node in isolation) — edge_context answers "what does THIS connection expose?".
# ---------------------------------------------------------------------------

_RISK_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _bump_risk(current: str, candidate: str) -> str:
    return candidate if _RISK_ORDER.get(candidate, 0) > _RISK_ORDER.get(current, 0) else current


def _edge_context_signals(
    edge_type: str,
    src_posture: Any,
    tgt_posture: Any,
) -> Dict[str, Any]:
    """Return edge-level danger context for a traversal step.

    Uses source and target PostureRow to explain WHY this edge is risky,
    independent of what's already shown in node risk_signals.

    Returns {} when no edge-level signals apply (clean traversal).
    Returns {"risk_level": str, "signals": [str]} otherwise.
    """
    et = edge_type.lower()
    signals: List[str] = []
    risk = "low"

    # ── Target signals: what does this edge give access to? ─────────────────
    if et in ("attached_to", "mounted_by"):
        tgt_enc = getattr(tgt_posture, "is_encrypted_at_rest", True) if tgt_posture else True
        if not tgt_enc:
            signals.append("Attached storage is not encrypted at rest — data readable in plaintext")
            risk = _bump_risk(risk, "high")
        tgt_dc = getattr(tgt_posture, "data_classification", None) if tgt_posture else None
        if tgt_dc in ("pii", "financial", "credentials"):
            signals.append(f"Attached storage contains {tgt_dc.upper()} data")
            risk = _bump_risk(risk, "critical")

    elif et in ("assumes", "can_assume"):
        tgt_cj = getattr(tgt_posture, "crown_jewel_type", "") if tgt_posture else ""
        if tgt_cj == "identity":
            signals.append("Target is a privileged identity crown jewel — full privilege escalation path")
            risk = _bump_risk(risk, "critical")
        tgt_mis = getattr(tgt_posture, "critical_misconfig_count", 0) if tgt_posture else 0
        if tgt_mis > 0:
            signals.append(f"Target role has {tgt_mis} critical misconfiguration(s)")
            risk = _bump_risk(risk, "high")

    elif et in ("grants_access_to", "can_access"):
        tgt_dc = getattr(tgt_posture, "data_classification", None) if tgt_posture else None
        if tgt_dc in ("pii", "financial", "credentials"):
            signals.append(f"Policy grants access to {tgt_dc.upper()} data resource")
            risk = _bump_risk(risk, "critical")
        elif tgt_dc == "internal":
            signals.append("Policy grants access to internal data resource")
            risk = _bump_risk(risk, "high")
        tgt_cj = getattr(tgt_posture, "crown_jewel_type", "") if tgt_posture else ""
        if tgt_cj:
            signals.append(f"Target is a crown jewel ({tgt_cj.replace('_', ' ')})")
            risk = _bump_risk(risk, "high")

    elif et == "grants_decrypt_to":
        signals.append("KMS key grants external decrypt — all data encrypted with this key is exposed")
        risk = _bump_risk(risk, "critical")

    elif et == "has_policy":
        tgt_mis = getattr(tgt_posture, "critical_misconfig_count", 0) if tgt_posture else 0
        if tgt_mis > 0:
            signals.append(f"Policy resource has {tgt_mis} critical misconfiguration(s)")
            risk = _bump_risk(risk, "medium")

    elif et == "member_of":
        tgt_cj = getattr(tgt_posture, "crown_jewel_type", "") if tgt_posture else ""
        if tgt_cj == "identity":
            signals.append("Group membership grants privileged identity access")
            risk = _bump_risk(risk, "high")

    elif et == "peered_with_external":
        signals.append("Traversal exits tenant boundary via cross-account VPC peering")
        risk = _bump_risk(risk, "high")

    elif et in ("peered_with", "connected_via"):
        src_waf = getattr(src_posture, "waf_protected", True) if src_posture else True
        if not src_waf:
            signals.append("Cross-VPC connection from resource without WAF protection")
            risk = _bump_risk(risk, "medium")

    elif et == "worker_node_of":
        tgt_mis = getattr(tgt_posture, "critical_misconfig_count", 0) if tgt_posture else 0
        if tgt_mis > 0:
            signals.append(f"EKS cluster has {tgt_mis} critical misconfiguration(s)")
            risk = _bump_risk(risk, "high")

    elif et == "has_endpoint":
        tgt_dc = getattr(tgt_posture, "data_classification", None) if tgt_posture else None
        if tgt_dc in ("pii", "financial", "credentials"):
            signals.append(f"Service endpoint exposes {tgt_dc.upper()} data")
            risk = _bump_risk(risk, "high")

    # ── Source signals: how capable is the attacker at the source hop? ───────
    if src_posture:
        src_epss = getattr(src_posture, "max_epss", None)
        if src_epss is not None and src_epss > 0.70:
            signals.append(f"Source has high-EPSS CVE ({src_epss:.2f}) — exploitation is likely")
            risk = _bump_risk(risk, "high")
        if getattr(src_posture, "has_active_cdr_actor", False):
            signals.append("Active CDR threat actor confirmed on source resource — traversal is live")
            risk = _bump_risk(risk, "critical")

    if not signals:
        return {}
    return {"risk_level": risk, "signals": signals}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def explain_path(
    node_uids: List[str],
    node_types: List[str],
    edge_types: List[str],
    hop_categories: List[str],
    severity: str,
    path_score: int,
    attack_vector: AttackVector,
    posture_lookup: Dict[str, Any],
    findings_lookup: Dict[str, Any],
) -> Dict[str, Any]:
    """Generate a full Orca-style step-by-step explanation for one attack path.

    Args:
        node_uids:      Ordered list of resource UIDs in the path (entry→crown).
        node_types:     Resource types per node.
        edge_types:     Relation types between consecutive nodes.
        hop_categories: Category per hop (internet/compute/data/identity/…).
        severity:       Path severity (critical/high/medium/low).
        path_score:     Integer path score 0-100.
        attack_vector:  AttackVector from classify_attack_vector().
        posture_lookup: Pre-fetched posture dict (uid → PostureRow).
        findings_lookup: Pre-fetched findings dict (uid → {misconfigs, cves, threat_detections}).

    Returns:
        Dict matching the documented output schema above.
    """
    if not node_uids:
        return {}

    entry_uid = node_uids[0]
    crown_uid = node_uids[-1]

    # Safely extend node_types to cover all nodes
    _node_types = list(node_types)
    while len(_node_types) < len(node_uids):
        _node_types.append("")

    entry_type = hop_categories[0] if hop_categories else "internet"
    entry_resource_type = _node_types[0]
    entry_posture = posture_lookup.get(entry_uid)

    crown_posture = posture_lookup.get(crown_uid)
    crown_type = (getattr(crown_posture, "crown_jewel_type", "") or "").replace("_", " ").title()
    crown_resource_type = _node_types[-1]

    entry_label = _friendly_type(entry_resource_type) if entry_resource_type else entry_type.capitalize()
    crown_label = _friendly_type(crown_resource_type) if crown_resource_type else crown_type or "Crown Jewel"

    title = _build_title(entry_type, entry_resource_type, crown_type.lower().replace(" ", "_"),
                         crown_resource_type, severity)
    summary = _build_summary(
        len(node_uids) - 1,
        attack_vector.vector_type,
        attack_vector.confidence,
        entry_label,
        crown_label,
        crown_type.lower().replace(" ", "_") or "data",
    )

    # Build steps
    steps: List[Dict[str, Any]] = []
    all_mitigations: List[str] = []

    for i, uid in enumerate(node_uids):
        posture = posture_lookup.get(uid)
        findings = findings_lookup.get(uid, {})
        rtype = _node_types[i] if i < len(_node_types) else ""
        hop_label = _friendly_type(rtype) if rtype else hop_categories[i].capitalize() if i < len(hop_categories) else "Resource"

        # Edge to next node
        edge = edge_types[i] if i < len(edge_types) else ""
        next_label = _friendly_type(_node_types[i + 1]) if i + 1 < len(_node_types) else ""
        action = _edge_action(edge, next_label) if edge else f"Entry point: {hop_label}"
        relation_to_next = f"{edge} →" if edge and i < len(node_uids) - 1 else "Crown Jewel (Target)"

        # MITRE technique for this hop (based on outgoing edge)
        technique = attack_vector.techniques[i] if i < len(attack_vector.techniques) else None
        mitre_str = f"{technique.technique_id} — {technique.technique_name}" if technique else ""
        tactic_str = technique.tactic_name if technique else ""

        risk_signals = _hop_risk_signals(uid, rtype, posture, findings)
        mitigations = _hop_mitigations(risk_signals)
        all_mitigations.extend(mitigations)

        # Edge context: explains why the outgoing edge from this hop is dangerous.
        # Uses source (current) and target (next) posture together.
        edge_ctx: Dict[str, Any] = {}
        if edge and i < len(node_uids) - 1:
            next_uid = node_uids[i + 1]
            next_posture = posture_lookup.get(next_uid)
            edge_ctx = _edge_context_signals(edge, posture, next_posture)

        step: Dict[str, Any] = {
            "step": i + 1,
            "uid": uid,
            "resource_type": rtype,
            "label": hop_label,
            "is_entry_point": (i == 0),
            "is_crown_jewel": (i == len(node_uids) - 1),
            "action": action if i > 0 else f"Entry via internet-exposed {hop_label}",
            "mitre_technique": mitre_str,
            "mitre_tactic": tactic_str,
            "risk_signals": risk_signals,
            "relation_to_next": relation_to_next,
        }
        if edge_ctx:
            step["edge_context"] = edge_ctx
        steps.append(step)

    # Build impact statement
    cj_type = getattr(crown_posture, "crown_jewel_type", "") or "data"
    impact_map = {
        "data":              f"Attacker can read, download, or exfiltrate all data stored in {crown_label}.",
        "data_warehouse":    f"Attacker can query and exfiltrate data warehouse contents of {crown_label}.",
        "secrets":           f"Attacker can retrieve credentials/secrets from {crown_label} and pivot further.",
        "identity":          f"Attacker can assume or modify identity permissions via {crown_label}.",
        "encryption_control": f"Attacker can decrypt, disable, or delete KMS keys protecting {crown_label}.",
        "infra_control":     f"Attacker can modify infrastructure configuration via {crown_label}.",
        "ai_model":          f"Attacker can poison training data or steal model artifacts from {crown_label}.",
        "code":              f"Attacker can modify source code or inject malicious code via {crown_label}.",
    }
    impact = impact_map.get(cj_type, f"Attacker gains full control over {crown_label}.")

    # Deduplicate mitigations
    seen: set = set()
    unique_mitigations = []
    for m in all_mitigations:
        if m not in seen:
            seen.add(m)
            unique_mitigations.append(m)

    return {
        "title": title,
        "severity": severity,
        "path_score": path_score,
        "vector_type": attack_vector.vector_type,
        "confidence": attack_vector.confidence,
        "summary": summary,
        "steps": steps,
        "tactic_sequence": attack_vector.tactic_sequence,
        "mitre_techniques": attack_vector.technique_ids(),
        "impact": impact,
        "mitigations": unique_mitigations[:8],   # cap at 8 mitigations per path
    }
