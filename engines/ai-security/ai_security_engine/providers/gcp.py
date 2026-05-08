"""GCP provider for AI Security engine — MITRE ATLAS 5-pillar analyze()."""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseAISecurityProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Valid ATLAS values (AC-S6, AC-S7)
# ---------------------------------------------------------------------------
VALID_PILLARS = frozenset({
    "model_security",
    "training_data_security",
    "inference_security",
    "supply_chain",
    "ai_governance",
})

ATLAS_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "AML.T0000": ("inference_security",     "HIGH",     "Model Evasion",        "Adversary crafts inputs to evade model detection."),
    "AML.T0001": ("training_data_security", "CRITICAL", "Data Poisoning",       "Adversary injects malicious data into training set."),
    "AML.T0002": ("inference_security",     "HIGH",     "Model Inversion",      "Adversary extracts training data from model outputs."),
    "AML.T0003": ("model_security",         "MEDIUM",   "Model Stealing",       "Adversary replicates model via repeated queries."),
    "AML.T0004": ("supply_chain",           "CRITICAL", "Backdoor ML Model",    "Adversary implants hidden trigger in model weights."),
    "AML.T0005": ("training_data_security", "CRITICAL", "Poison Training Data", "Adversary corrupts training data pipeline."),
}

VALID_TECHNIQUES = frozenset(ATLAS_TECHNIQUES.keys())

# ---------------------------------------------------------------------------
# GCP AI/ML resource types consumed from discovery_findings (story spec)
# ---------------------------------------------------------------------------
GCP_AI_RESOURCE_TYPES = {
    "AIPlatform::Model",
    "AIPlatform::Endpoint",
    "VertexAI::Dataset",
    "AutoML::Model",
    # Proxy resource types present in discovery_findings
    "storage.googleapis.com/Bucket",
    "iam.googleapis.com/ServiceAccount",
    "compute.googleapis.com/Firewall",
    "compute.googleapis.com/Subnetwork",
    "compute.googleapis.com/Route",
}


def _make_finding_id(atlas_pillar: str, atlas_technique: Optional[str],
                     resource_uid: str, account_id: str, region: str) -> str:
    """Deterministic finding_id per AC-S3.

    sha256(f"{atlas_pillar}_{atlas_technique}|{resource_uid}|{account_id}|{region}")[:16]
    """
    technique_part = atlas_technique or "none"
    raw = f"{atlas_pillar}_{technique_part}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _validate_pillar(pillar: str) -> str:
    """Validate atlas_pillar (AC-S6)."""
    if pillar not in VALID_PILLARS:
        logger.warning("Unknown atlas_pillar '%s' — defaulting to ai_governance", pillar)
        return "ai_governance"
    return pillar


def _validate_technique(technique: Optional[str]) -> Optional[str]:
    """Validate atlas_technique (AC-S7). Unknown techniques logged at WARNING."""
    if technique is None:
        return None
    if technique not in VALID_TECHNIQUES:
        logger.warning("Unknown atlas_technique '%s' — dropping technique field", technique)
        return None
    return technique


def _atlas_detail(technique_id: Optional[str]) -> Dict[str, str]:
    """Return atlas_detail dict for a given technique ID."""
    if not technique_id:
        return {}
    row = ATLAS_TECHNIQUES.get(technique_id)
    if not row:
        return {}
    return {"technique_id": technique_id, "technique_name": row[2], "description": row[3]}


def _finding(
    rule_id: str,
    resource_uid: str,
    resource_type: str,
    account_id: str,
    region: str,
    tenant_id: str,
    scan_run_id: str,
    severity: str,
    pillar: str,
    atlas_technique: Optional[str],
    title: str,
    detail: str,
    status: str = "FAIL",
) -> Dict[str, Any]:
    """Build a complete ATLAS finding dict for GCP."""
    validated_pillar = _validate_pillar(pillar)
    validated_technique = _validate_technique(atlas_technique)
    now = datetime.now(timezone.utc)
    return {
        "finding_id": _make_finding_id(validated_pillar, validated_technique,
                                        resource_uid, account_id, region),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": "gcp",
        "region": region,
        "resource_uid": resource_uid,
        "resource_type": resource_type,
        "severity": severity,
        "status": status,
        "atlas_pillar": validated_pillar,
        "pillar": validated_pillar,
        "atlas_technique": validated_technique,
        "atlas_detail": _atlas_detail(validated_technique),
        "blast_radius_score": 0,
        "rule_id": rule_id,
        "title": title,
        "detail": detail,
        "first_seen_at": now,
        "last_seen_at": now,
    }


class GCPAISecurityProvider(BaseAISecurityProvider):
    """GCP AI security provider — MITRE ATLAS 5-pillar.

    Queries discovery_findings for native GCP AI/ML resource types
    (AIPlatform::Model, AIPlatform::Endpoint, VertexAI::Dataset, AutoML::Model)
    and proxy resource types (GCS buckets, Service Accounts, Firewall rules)
    to ensure AI workloads meet minimum ATLAS posture.
    """

    @property
    def discovery_services(self) -> List[str]:
        """GCP AI/ML service names targeted by the scanner."""
        return [
            "aiplatform", "automl", "vision", "language",
            "speech", "videointelligence", "translate",
            "documentai", "dialogflow", "discoveryengine",
        ]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        """Inventory resource_type prefixes for GCP AI assets."""
        return ["aiplatform.", "automl.", "vision.", "dialogflow."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Produce MITRE ATLAS findings for GCP AI/ML resources.

        Queries discovery_findings for native GCP Vertex AI resource types and
        proxy resource types (GCS, Service Accounts, Firewall) with tenant_id
        filter on all queries (AC-S1).  Model endpoint URLs and dataset paths
        are never logged (AC-S2).

        Args:
            scan_run_id: Current pipeline scan run identifier.
            tenant_id: Tenant identifier — all queries filtered by this.
            account_id: GCP project identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: Unused for GCP.

        Returns:
            List of ATLAS finding dicts.
        """
        findings: List[Dict[str, Any]] = []

        try:
            cur = discoveries_conn.cursor()
            cur.execute(
                """
                SELECT resource_uid, resource_type, region, emitted_fields
                FROM discovery_findings
                WHERE tenant_id = %s
                  AND scan_run_id = %s
                  AND provider = 'gcp'
                """,
                (tenant_id, scan_run_id),
            )
            rows = cur.fetchall()
            cur.close()
        except Exception as exc:
            logger.error("GCP AI analyze(): DB query failed: %s", exc)
            return findings

        logger.info("GCP AI analyze(): %d resource rows for scan %s", len(rows), scan_run_id)

        resource_types_seen = {r[1] for r in rows}
        has_storage = "storage.googleapis.com/Bucket" in resource_types_seen
        has_sa = "iam.googleapis.com/ServiceAccount" in resource_types_seen
        has_firewall = "compute.googleapis.com/Firewall" in resource_types_seen
        has_aiplatform_model = "AIPlatform::Model" in resource_types_seen
        has_aiplatform_endpoint = "AIPlatform::Endpoint" in resource_types_seen
        has_vertex_dataset = "VertexAI::Dataset" in resource_types_seen

        acct_uid = f"gcp:{account_id}:ai_governance"

        for resource_uid, resource_type, res_region, ef in rows:
            if not ef:
                ef = {}
            r_region = res_region or "global"

            # ------------------------------------------------------------------
            # Pillar 1 — Model Security: AIPlatform::Model
            # ------------------------------------------------------------------
            if resource_type == "AIPlatform::Model":
                # No version aliases → supply chain (model lineage)
                version_aliases = ef.get("versionAliases") or []
                if not version_aliases:
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.model_security.aiplatform_model_no_version_aliases",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="MEDIUM",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="Vertex AI Model has no version aliases — model lineage tracking gap",
                        detail=(
                            "No version aliases configured. Version aliases enable immutable "
                            "model references and reduce model-stealing risk from version confusion."
                        ),
                    ))

                # Encryption spec missing → supply chain
                encryption_spec = ef.get("encryptionSpec") or {}
                if not encryption_spec:
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.supply_chain.aiplatform_model_no_cmek",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="supply_chain",
                        atlas_technique="AML.T0004",
                        title="Vertex AI Model has no CMEK encryption — model artifact integrity unverified",
                        detail=(
                            "No encryptionSpec configured for model artifacts. Without CMEK, "
                            "model artifact provenance cannot be independently verified against "
                            "supply-chain tampering."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security: AIPlatform::Endpoint
            # ------------------------------------------------------------------
            if resource_type == "AIPlatform::Endpoint":
                # Public endpoint without traffic split → evasion risk
                network = ef.get("network", "")
                traffic_split = ef.get("trafficSplit") or {}

                if not network:
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.inference_security.aiplatform_endpoint_no_vpc_network",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="inference_security",
                        atlas_technique="AML.T0000",
                        title="Vertex AI Endpoint has no VPC network configured — public inference exposure",
                        detail=(
                            "No VPC network attached to the endpoint. Public Vertex AI endpoints "
                            "without network restrictions are susceptible to adversarial evasion attacks."
                        ),
                    ))

                # No encryption spec → model inversion risk
                encryption_spec = ef.get("encryptionSpec") or {}
                if not encryption_spec:
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.inference_security.aiplatform_endpoint_no_cmek",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="inference_security",
                        atlas_technique="AML.T0002",
                        title="Vertex AI Endpoint has no CMEK encryption — inference data protection gap",
                        detail=(
                            "No encryptionSpec on inference endpoint. Inference request/response data "
                            "is not encrypted with customer-managed keys, enabling model inversion."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 2 — Training Data Security: VertexAI::Dataset
            # ------------------------------------------------------------------
            if resource_type == "VertexAI::Dataset":
                encryption_spec = ef.get("encryptionSpec") or {}
                labels = ef.get("labels") or {}

                if not encryption_spec:
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.training_data_security.vertex_dataset_no_cmek",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="training_data_security",
                        atlas_technique="AML.T0001",
                        title="Vertex AI Dataset has no CMEK encryption — training data poisoning risk",
                        detail=(
                            "No encryptionSpec configured for training dataset. Without CMEK, "
                            "dataset integrity cannot be cryptographically verified and poisoning "
                            "attacks may go undetected."
                        ),
                    ))

                # Missing data classification labels → governance gap
                if not labels.get("data-classification") and not labels.get("sensitivity"):
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.ai_governance.vertex_dataset_no_classification_label",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="MEDIUM",
                        pillar="ai_governance",
                        atlas_technique=None,
                        title="Vertex AI Dataset has no data classification label",
                        detail=(
                            "No 'data-classification' or 'sensitivity' label on training dataset. "
                            "Data classification labels are required for AI governance and NIST AI RMF compliance."
                        ),
                    ))

                # No provenance tracking → AML.T0005
                metadata = ef.get("metadata") or {}
                if not metadata:
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.training_data_security.vertex_dataset_no_metadata",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="training_data_security",
                        atlas_technique="AML.T0005",
                        title="Vertex AI Dataset has no metadata/provenance — training data poisoning detection gap",
                        detail=(
                            "No metadata recorded for this dataset. Without provenance tracking, "
                            "poisoned data insertions cannot be traced to their source."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 2 — Training Data Security: GCS Bucket checks
            # ------------------------------------------------------------------
            if resource_type == "storage.googleapis.com/Bucket":
                iam_config = ef.get("iamConfiguration") or {}
                public_access = iam_config.get("publicAccessPrevention", "")
                uniform_bucket_iam = iam_config.get("uniformBucketLevelAccess") or {}
                uniform_enabled = (
                    uniform_bucket_iam.get("enabled", False)
                    if isinstance(uniform_bucket_iam, dict)
                    else False
                )

                if public_access not in ("enforced", "inherited"):
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.training_data_security.gcs_public_access_not_enforced",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="training_data_security",
                        atlas_technique="AML.T0001",
                        title="GCS bucket public access prevention not enforced — AI training data at risk",
                        detail=(
                            f"publicAccessPrevention='{public_access}'. Training datasets stored "
                            "in this bucket may be accessible to unauthenticated principals."
                        ),
                    ))

                if not uniform_enabled:
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.training_data_security.gcs_non_uniform_iam",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="training_data_security",
                        atlas_technique="AML.T0005",
                        title="GCS bucket uses ACL-based access — training data poisoning risk",
                        detail=(
                            "Uniform bucket-level IAM is disabled. Object-level ACLs can grant "
                            "overly broad write access, enabling training data poisoning."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 1 — Model Security: Service Account checks
            # ------------------------------------------------------------------
            if resource_type == "iam.googleapis.com/ServiceAccount":
                sa_keys = ef.get("keys") or []
                if isinstance(sa_keys, list) and len(sa_keys) > 0:
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.model_security.sa_user_managed_keys",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="GCP Service Account has user-managed keys — AI model identity theft risk",
                        detail=(
                            f"Service account has {len(sa_keys)} user-managed key(s). "
                            "Leaked SA keys allow model-stealing via Vertex AI API access."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security: Firewall rule checks
            # ------------------------------------------------------------------
            if resource_type == "compute.googleapis.com/Firewall":
                direction = ef.get("direction", "")
                allowed_rules = ef.get("allowed") or []
                source_ranges = ef.get("sourceRanges") or []

                is_public_inbound = (
                    direction == "INGRESS"
                    and ("0.0.0.0/0" in source_ranges or "::/0" in source_ranges)
                )
                if is_public_inbound and allowed_rules:
                    for rule in allowed_rules:
                        if not isinstance(rule, dict):
                            continue
                        ports = rule.get("ports") or []
                        ml_ports = {"80", "443", "8080", "8443", "8501", "8500", "5000"}
                        exposed_ports = set(str(p) for p in ports) & ml_ports
                        if exposed_ports or not ports:
                            findings.append(_finding(
                                rule_id="gcp.ai_sec.inference_security.firewall_public_ingress",
                                resource_uid=resource_uid,
                                resource_type=resource_type,
                                account_id=account_id,
                                region=r_region,
                                tenant_id=tenant_id,
                                scan_run_id=scan_run_id,
                                severity="HIGH",
                                pillar="inference_security",
                                atlas_technique="AML.T0002",
                                title="GCP Firewall allows public ingress — AI inference endpoint exposed",
                                detail=(
                                    f"Firewall rule allows ingress from 0.0.0.0/0 on "
                                    f"ports {exposed_ports or 'all'}. "
                                    "Vertex AI and TF Serving endpoints may be publicly reachable."
                                ),
                            ))
                            break

        # ------------------------------------------------------------------
        # Pillar 5 — AI Governance: account-level checks
        # ------------------------------------------------------------------
        if not has_storage:
            findings.append(_finding(
                rule_id="gcp.ai_sec.ai_governance.no_gcs_bucket",
                resource_uid=acct_uid,
                resource_type="GCPProject",
                account_id=account_id,
                region="global",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="MEDIUM",
                pillar="ai_governance",
                atlas_technique=None,
                title="No GCS buckets found — AI training data governance cannot be assessed",
                detail=(
                    "No Cloud Storage buckets detected in this project. "
                    "Verify AI training data is not stored in unscanned regions/projects."
                ),
            ))

        if not has_sa:
            findings.append(_finding(
                rule_id="gcp.ai_sec.ai_governance.no_service_accounts",
                resource_uid=acct_uid,
                resource_type="GCPProject",
                account_id=account_id,
                region="global",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="ai_governance",
                atlas_technique=None,
                title="No GCP Service Accounts found — AI workload identity governance gap",
                detail=(
                    "No Service Accounts detected. AI workloads on Vertex AI require "
                    "dedicated service accounts with least-privilege IAM bindings."
                ),
            ))

        if not has_firewall:
            findings.append(_finding(
                rule_id="gcp.ai_sec.supply_chain.no_firewall",
                resource_uid=acct_uid,
                resource_type="GCPProject",
                account_id=account_id,
                region="global",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="supply_chain",
                atlas_technique="AML.T0004",
                title="No GCP Firewall rules found — AI model registry and artifact store unprotected",
                detail=(
                    "No Compute Firewall rules detected. Model registries and Artifact Registry "
                    "should be protected by VPC firewall rules to prevent supply-chain attacks."
                ),
            ))

        # Pillar 2 — Training Data: no Vertex AI dataset found
        if not has_vertex_dataset:
            findings.append(_finding(
                rule_id="gcp.ai_sec.training_data_security.no_vertex_datasets",
                resource_uid=acct_uid,
                resource_type="GCPProject",
                account_id=account_id,
                region="global",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="LOW",
                pillar="training_data_security",
                atlas_technique="AML.T0001",
                title="No Vertex AI Datasets found — training data provenance cannot be assessed",
                detail=(
                    "No VertexAI::Dataset resources found. Enable Vertex AI dataset discovery "
                    "to assess training data provenance and poisoning exposure."
                ),
            ))

        logger.info(
            "GCP AI analyze(): produced %d ATLAS findings for scan %s",
            len(findings), scan_run_id,
        )
        return findings
