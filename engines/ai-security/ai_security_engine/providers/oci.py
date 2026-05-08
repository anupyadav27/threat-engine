"""OCI provider for AI Security engine — MITRE ATLAS 5-pillar analyze()."""
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
# OCI AI/ML resource types consumed from discovery_findings (story spec)
# ---------------------------------------------------------------------------
OCI_AI_RESOURCE_TYPES = {
    "DataScience::Model",
    "DataScience::Project",
    "AnomalyDetection::Model",
    # Proxy resource types present in discovery_findings
    "oci.audit/Event",
    "oci.core/SecurityList",
    "oci.objectstorage/Bucket",
    "oci.core/Vcn",
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
    """Build a complete ATLAS finding dict for OCI."""
    validated_pillar = _validate_pillar(pillar)
    validated_technique = _validate_technique(atlas_technique)
    now = datetime.now(timezone.utc)
    return {
        "finding_id": _make_finding_id(validated_pillar, validated_technique,
                                        resource_uid, account_id, region),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": "oci",
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


class OCIAISecurityProvider(BaseAISecurityProvider):
    """OCI AI security provider — MITRE ATLAS 5-pillar.

    Queries discovery_findings for OCI DataScience and AnomalyDetection
    resource types (DataScience::Model, DataScience::Project,
    AnomalyDetection::Model) and proxy resource types (audit events,
    security lists, object storage, VCN) to ensure AI workloads meet
    minimum ATLAS posture.
    """

    @property
    def discovery_services(self) -> List[str]:
        """OCI AI/ML service names targeted by the scanner."""
        return ["datascience", "aidocument", "ailanguage", "aivision"]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        """Inventory resource_type prefixes for OCI AI assets."""
        return ["datascience.", "aidocument."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Produce MITRE ATLAS findings for OCI AI/ML resources.

        Queries discovery_findings for native OCI DataScience resource types
        and proxy resource types (audit, security lists, object storage, VCN)
        with tenant_id filter on all queries (AC-S1).

        Args:
            scan_run_id: Current pipeline scan run identifier.
            tenant_id: Tenant identifier — all queries filtered by this.
            account_id: OCI tenancy identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: Unused for OCI.

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
                  AND provider = 'oci'
                """,
                (tenant_id, scan_run_id),
            )
            rows = cur.fetchall()
            cur.close()
        except Exception as exc:
            logger.error("OCI AI analyze(): DB query failed: %s", exc)
            return findings

        logger.info("OCI AI analyze(): %d resource rows for scan %s", len(rows), scan_run_id)

        resource_types_seen = {r[1] for r in rows}
        has_audit = "oci.audit/Event" in resource_types_seen
        has_seclist = "oci.core/SecurityList" in resource_types_seen
        has_bucket = "oci.objectstorage/Bucket" in resource_types_seen
        has_vcn = "oci.core/Vcn" in resource_types_seen
        has_datascience_model = "DataScience::Model" in resource_types_seen
        has_datascience_project = "DataScience::Project" in resource_types_seen
        has_anomaly_model = "AnomalyDetection::Model" in resource_types_seen

        acct_uid = f"oci:{account_id}:ai_governance"

        for resource_uid, resource_type, res_region, ef in rows:
            if not ef:
                ef = {}
            r_region = res_region or "ap-mumbai-1"

            # ------------------------------------------------------------------
            # Pillar 1 — Model Security: DataScience::Model
            # ------------------------------------------------------------------
            if resource_type == "DataScience::Model":
                # No custom metadata → governance / provenance gap
                custom_metadata = ef.get("customMetadataList") or []
                if not custom_metadata:
                    findings.append(_finding(
                        rule_id="oci.ai_sec.model_security.datascience_model_no_metadata",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="MEDIUM",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="OCI DataScience Model has no custom metadata — model lineage tracking gap",
                        detail=(
                            "No customMetadataList on model artifact. Model provenance, training "
                            "data references, and signing information should be recorded in metadata."
                        ),
                    ))

                # Lifecycle state not Active → governance review needed
                lifecycle = ef.get("lifecycleState", "")
                if lifecycle and lifecycle not in ("ACTIVE",):
                    findings.append(_finding(
                        rule_id="oci.ai_sec.ai_governance.datascience_model_non_active",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="LOW",
                        pillar="ai_governance",
                        atlas_technique=None,
                        title=f"OCI DataScience Model in non-active lifecycle state: {lifecycle}",
                        detail=(
                            f"Model lifecycleState='{lifecycle}'. Non-active models should be "
                            "reviewed and either promoted or archived to maintain governance posture."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 2 — Training Data Security: DataScience::Project
            # ------------------------------------------------------------------
            if resource_type == "DataScience::Project":
                # Project without description → governance gap (model card equivalent)
                description = ef.get("description", "")
                if not description:
                    findings.append(_finding(
                        rule_id="oci.ai_sec.training_data_security.datascience_project_no_description",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="LOW",
                        pillar="training_data_security",
                        atlas_technique="AML.T0005",
                        title="OCI DataScience Project has no description — training data provenance gap",
                        detail=(
                            "No project description. DataScience Projects should document "
                            "training data sources and data classification to enable poisoning detection."
                        ),
                    ))

                # No free-form tags → governance gap
                freeform_tags = ef.get("freeformTags") or {}
                if not freeform_tags:
                    findings.append(_finding(
                        rule_id="oci.ai_sec.ai_governance.datascience_project_no_tags",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="LOW",
                        pillar="ai_governance",
                        atlas_technique=None,
                        title="OCI DataScience Project has no freeform tags — AI governance gap",
                        detail=(
                            "No freeformTags on project. Tags should include data-owner, "
                            "data-classification, and cost-center for AI governance compliance."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 4 — Supply Chain: AnomalyDetection::Model
            # ------------------------------------------------------------------
            if resource_type == "AnomalyDetection::Model":
                model_training_results = ef.get("modelTrainingResults") or {}
                if not model_training_results:
                    findings.append(_finding(
                        rule_id="oci.ai_sec.supply_chain.anomaly_model_no_training_results",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="supply_chain",
                        atlas_technique="AML.T0004",
                        title="OCI AnomalyDetection Model has no training results recorded — provenance gap",
                        detail=(
                            "No modelTrainingResults on anomaly detection model. Training results "
                            "including data hash and metrics should be recorded to detect backdoor "
                            "model substitution in the supply chain."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 5 — AI Governance: Audit event analysis
            # ------------------------------------------------------------------
            if resource_type == "oci.audit/Event":
                event_type = ef.get("eventType", "") or ef.get("type", "")
                if "datascience" in event_type.lower() or "datasci" in event_type.lower():
                    principal = ef.get("principalName", "") or ef.get("subject", "")
                    if not principal:
                        findings.append(_finding(
                            rule_id="oci.ai_sec.ai_governance.datascience_unauthenticated_event",
                            resource_uid=resource_uid,
                            resource_type=resource_type,
                            account_id=account_id,
                            region=r_region,
                            tenant_id=tenant_id,
                            scan_run_id=scan_run_id,
                            severity="CRITICAL",
                            pillar="ai_governance",
                            atlas_technique="AML.T0002",
                            title="OCI DataScience API call without authenticated principal in audit log",
                            detail=(
                                f"Audit event type={event_type} has no principalName. "
                                "This may indicate unauthenticated access to AI/ML resources."
                            ),
                        ))

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security: SecurityList checks
            # ------------------------------------------------------------------
            if resource_type == "oci.core/SecurityList":
                ingress_rules = ef.get("ingressSecurityRules") or []
                for rule in ingress_rules:
                    if not isinstance(rule, dict):
                        continue
                    source = rule.get("source", "")
                    protocol = str(rule.get("protocol", ""))
                    tcp_options = rule.get("tcpOptions") or {}
                    dest_port_range = tcp_options.get("destinationPortRange") or {}
                    max_port = dest_port_range.get("max", 0)
                    min_port = dest_port_range.get("min", 0)

                    if source in ("0.0.0.0/0", "::/0"):
                        findings.append(_finding(
                            rule_id="oci.ai_sec.inference_security.seclist_public_ingress",
                            resource_uid=resource_uid,
                            resource_type=resource_type,
                            account_id=account_id,
                            region=r_region,
                            tenant_id=tenant_id,
                            scan_run_id=scan_run_id,
                            severity="HIGH",
                            pillar="inference_security",
                            atlas_technique="AML.T0002",
                            title="OCI Security List allows public ingress — AI inference endpoint exposed",
                            detail=(
                                f"Ingress rule allows traffic from {source} "
                                f"protocol={protocol} ports {min_port}-{max_port}. "
                                "OCI DataScience model deployment endpoints may be publicly reachable."
                            ),
                        ))
                        break

            # ------------------------------------------------------------------
            # Pillar 2 — Training Data Security: Object Storage checks
            # ------------------------------------------------------------------
            if resource_type == "oci.objectstorage/Bucket":
                public_access_type = ef.get("publicAccessType", "NoPublicAccess")
                versioning = ef.get("versioning", "Disabled")

                if public_access_type != "NoPublicAccess":
                    findings.append(_finding(
                        rule_id="oci.ai_sec.training_data_security.bucket_public_access",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="training_data_security",
                        atlas_technique="AML.T0001",
                        title="OCI Object Storage bucket is publicly accessible — AI training data at risk",
                        detail=(
                            f"publicAccessType='{public_access_type}'. Training datasets may be "
                            "readable by unauthenticated principals, enabling data poisoning."
                        ),
                    ))

                if versioning == "Disabled":
                    findings.append(_finding(
                        rule_id="oci.ai_sec.training_data_security.bucket_no_versioning",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="training_data_security",
                        atlas_technique="AML.T0005",
                        title="OCI Object Storage bucket versioning disabled — training data integrity unprotected",
                        detail=(
                            "Versioning is disabled. Overwrite attacks on training datasets "
                            "cannot be detected or rolled back."
                        ),
                    ))

        # ------------------------------------------------------------------
        # Account-level governance checks
        # ------------------------------------------------------------------
        if not has_audit:
            findings.append(_finding(
                rule_id="oci.ai_sec.ai_governance.no_audit_events",
                resource_uid=acct_uid,
                resource_type="OCITenancy",
                account_id=account_id,
                region="ap-mumbai-1",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="ai_governance",
                atlas_technique=None,
                title="No OCI Audit events found — AI workload activity cannot be monitored",
                detail=(
                    "No audit events detected. OCI Audit must be enabled to track "
                    "DataScience API calls and detect anomalous AI model access."
                ),
            ))

        if not has_vcn:
            findings.append(_finding(
                rule_id="oci.ai_sec.inference_security.no_vcn",
                resource_uid=acct_uid,
                resource_type="OCITenancy",
                account_id=account_id,
                region="ap-mumbai-1",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="inference_security",
                atlas_technique="AML.T0002",
                title="No OCI VCN found — AI inference workloads may lack network isolation",
                detail=(
                    "No Virtual Cloud Networks detected. OCI DataScience notebooks and "
                    "model deployments should run in private subnets within a VCN."
                ),
            ))

        if not has_seclist:
            findings.append(_finding(
                rule_id="oci.ai_sec.model_security.no_security_list",
                resource_uid=acct_uid,
                resource_type="OCITenancy",
                account_id=account_id,
                region="ap-mumbai-1",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="MEDIUM",
                pillar="model_security",
                atlas_technique="AML.T0003",
                title="No OCI Security Lists found — AI model endpoint access control not verified",
                detail=(
                    "No Security Lists detected. Model serving endpoints on OCI DataScience "
                    "require security list rules to restrict inbound access."
                ),
            ))

        if not has_datascience_model:
            findings.append(_finding(
                rule_id="oci.ai_sec.supply_chain.datascience_model_not_enumerated",
                resource_uid=acct_uid,
                resource_type="OCITenancy",
                account_id=account_id,
                region="ap-mumbai-1",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="MEDIUM",
                pillar="supply_chain",
                atlas_technique="AML.T0004",
                title="OCI DataScience Model not found in discovery — supply chain assessment limited",
                detail=(
                    "DataScience::Model resources not found in discovery_findings. "
                    "Enable OCI DataScience discovery to evaluate model provenance and "
                    "supply chain integrity."
                ),
            ))

        logger.info(
            "OCI AI analyze(): produced %d ATLAS findings for scan %s",
            len(findings), scan_run_id,
        )
        return findings
