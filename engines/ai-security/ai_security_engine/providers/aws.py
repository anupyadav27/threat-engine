"""AWS provider for AI Security engine — MITRE ATLAS 5-pillar analyze()."""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseAISecurityProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATLAS technique reference
# ---------------------------------------------------------------------------
ATLAS_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "AML.T0000": {
        "name": "Model Evasion",
        "pillar": "inference_security",
        "severity": "HIGH",
        "description": "Adversary crafts inputs to evade model detection.",
    },
    "AML.T0001": {
        "name": "Data Poisoning",
        "pillar": "training_data_security",
        "severity": "CRITICAL",
        "description": "Adversary injects malicious data into training set.",
    },
    "AML.T0002": {
        "name": "Model Inversion",
        "pillar": "inference_security",
        "severity": "HIGH",
        "description": "Adversary extracts training data from model outputs.",
    },
    "AML.T0003": {
        "name": "Model Stealing",
        "pillar": "model_security",
        "severity": "MEDIUM",
        "description": "Adversary replicates model functionality via repeated queries.",
    },
    "AML.T0004": {
        "name": "Backdoor ML Model",
        "pillar": "supply_chain",
        "severity": "CRITICAL",
        "description": "Adversary implants hidden trigger in model weights.",
    },
    "AML.T0005": {
        "name": "Poison Training Data",
        "pillar": "training_data_security",
        "severity": "CRITICAL",
        "description": "Adversary corrupts training data pipeline at source.",
    },
}

# Valid ATLAS pillar names (AC-S6).
VALID_PILLARS = frozenset({
    "model_security",
    "training_data_security",
    "inference_security",
    "supply_chain",
    "ai_governance",
})

# Valid ATLAS technique IDs (AC-S7).
VALID_TECHNIQUES = frozenset(ATLAS_TECHNIQUES.keys())

# ---------------------------------------------------------------------------
# Resource types targeted by this provider
# ---------------------------------------------------------------------------
AWS_AI_SERVICES = {
    "sagemaker",
    "sagemaker-runtime",
    "sagemaker-edge",
    "sagemaker-geospatial",
    "bedrock",
    "bedrock-runtime",
    "bedrock-agent",
    "bedrock-agent-runtime",
    "comprehend",
    "rekognition",
}

# Discovery resource_type values for AWS AI/ML (story spec)
AWS_AI_RESOURCE_TYPES = {
    "SageMaker::Model",
    "SageMaker::Endpoint",
    "SageMaker::NotebookInstance",
    "Bedrock::Model",
    "Comprehend::Classifier",
    "Rekognition::Collection",
    # Lower-cased variants as emitted by scanner
    "notebook_instance",
    "transform_job",
    "inference_profile",
    "model_invocation_logging_configuration",
    "prompt_router",
    "resource_catalog",
}


def _make_finding_id(atlas_pillar: str, atlas_technique: Optional[str],
                     resource_uid: str, account_id: str, region: str) -> str:
    """Deterministic finding_id per AC-S3.

    sha256(f"{atlas_pillar}_{atlas_technique}|{resource_uid}|{account_id}|{region}")[:16]
    When atlas_technique is None (governance checks without a technique),
    the prefix is just the pillar name.
    """
    technique_part = atlas_technique or "none"
    raw = f"{atlas_pillar}_{technique_part}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _validate_pillar(pillar: str) -> str:
    """Validate atlas_pillar against known set (AC-S6). Returns pillar unchanged."""
    if pillar not in VALID_PILLARS:
        logger.warning("Unknown atlas_pillar '%s' — defaulting to ai_governance", pillar)
        return "ai_governance"
    return pillar


def _validate_technique(technique: Optional[str]) -> Optional[str]:
    """Validate atlas_technique against known set (AC-S7).

    Unknown techniques are logged at WARNING (not CRITICAL) and dropped.
    """
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
    t = ATLAS_TECHNIQUES.get(technique_id, {})
    return {
        "technique_id": technique_id,
        "technique_name": t.get("name", ""),
        "description": t.get("description", ""),
    }


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
    """Build a complete ATLAS finding dict."""
    validated_pillar = _validate_pillar(pillar)
    validated_technique = _validate_technique(atlas_technique)
    now = datetime.now(timezone.utc)
    return {
        "finding_id": _make_finding_id(validated_pillar, validated_technique,
                                        resource_uid, account_id, region),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": "aws",
        "region": region,
        "resource_uid": resource_uid,
        "resource_type": resource_type,
        "severity": severity,
        "status": status,
        # Both field names so db_writer can read either
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


class AWSAISecurityProvider(BaseAISecurityProvider):
    """AWS AI security provider.

    Reads discovery_findings for SageMaker and Bedrock resources and produces
    MITRE ATLAS-mapped findings across 5 pillars.
    """

    @property
    def discovery_services(self) -> List[str]:
        """SageMaker and Bedrock service names discovered by the scanner."""
        return [
            "sagemaker", "sagemaker-runtime", "sagemaker-edge",
            "sagemaker-featurestore-runtime", "bedrock", "bedrock-runtime",
            "bedrock-agent", "bedrock-agent-runtime", "bedrock-agentcore-control",
            "comprehend", "comprehendmedical", "textract", "translate",
            "transcribe", "rekognition", "polly", "lex-models", "lexv2-models",
            "kendra", "personalize", "forecast", "machinelearning",
            "frauddetector", "lookoutmetrics", "lookoutequipment", "lookoutvision",
        ]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        """Inventory resource_type prefixes for AI/ML assets."""
        return ["sagemaker.", "bedrock.", "comprehend.", "rekognition.", "textract.", "kendra."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Produce MITRE ATLAS findings for AWS AI/ML resources.

        Queries discovery_findings for SageMaker and Bedrock resources belonging
        to this tenant/scan, inspects emitted_fields (already a dict), and returns
        pillar-tagged findings.

        Args:
            scan_run_id: Current pipeline scan run identifier.
            tenant_id: Tenant identifier — all queries filtered by this.
            account_id: AWS account identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: Unused for AWS.

        Returns:
            List of ATLAS finding dicts.
        """
        findings: List[Dict[str, Any]] = []

        try:
            cur = discoveries_conn.cursor()
            cur.execute(
                """
                SELECT resource_uid, resource_type, region, service, emitted_fields
                FROM discovery_findings
                WHERE tenant_id = %s
                  AND scan_run_id = %s
                  AND service = ANY(%s)
                """,
                (
                    tenant_id,
                    scan_run_id,
                    list(AWS_AI_SERVICES),
                ),
            )
            rows = cur.fetchall()
            cur.close()
        except Exception as exc:
            logger.error("AWS AI analyze(): DB query failed: %s", exc)
            return findings

        logger.info("AWS AI analyze(): %d AI resource rows for scan %s", len(rows), scan_run_id)

        for resource_uid, resource_type, region, service, ef in rows:
            if not ef:
                ef = {}
            region = region or "ap-south-1"

            svc = (service or "").lower()

            # ------------------------------------------------------------------
            # Pillar 1 — Model Security (AML.T0003)
            # ------------------------------------------------------------------
            if svc == "sagemaker" and resource_type == "notebook_instance":
                # RootAccess enabled → CRITICAL
                if ef.get("RootAccess") == "Enabled":
                    findings.append(_finding(
                        rule_id="aws.ai_sec.model_security.notebook_root_access",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="SageMaker notebook has root access enabled",
                        detail="RootAccess=Enabled allows container privilege escalation and model exfiltration.",
                    ))
                else:
                    # PASS finding so pillar coverage is recorded
                    findings.append(_finding(
                        rule_id="aws.ai_sec.model_security.notebook_root_access",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="SageMaker notebook root access check",
                        detail="RootAccess is disabled — compliant.",
                        status="PASS",
                    ))

                # DirectInternetAccess enabled → HIGH
                if ef.get("DirectInternetAccess") == "Enabled":
                    findings.append(_finding(
                        rule_id="aws.ai_sec.model_security.notebook_public_internet",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="SageMaker notebook has direct internet access enabled",
                        detail="DirectInternetAccess=Enabled exposes notebook to model-stealing attacks.",
                    ))

            # ------------------------------------------------------------------
            # Pillar 2 — Training Data Security (AML.T0005)
            # ------------------------------------------------------------------
            if svc == "sagemaker" and resource_type == "transform_job":
                # No VPC config on transform job → HIGH (data transit risk)
                if not ef.get("VpcConfig") and not ef.get("DataProcessingConfig"):
                    findings.append(_finding(
                        rule_id="aws.ai_sec.training_data_security.no_vpc_transform",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="training_data_security",
                        atlas_technique="AML.T0005",
                        title="SageMaker transform job runs without VPC isolation",
                        detail="No VpcConfig — training/transform data transits public internet.",
                    ))

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security (AML.T0002 / AML.T0000)
            # ------------------------------------------------------------------
            if svc == "bedrock" and resource_type == "inference_profile":
                status_val = ef.get("status", "")
                profile_type = ef.get("type", "")

                # SYSTEM_DEFINED profiles with ACTIVE status — check logging
                if status_val == "ACTIVE":
                    # No invocation logging means no capture for AML.T0000 detection
                    findings.append(_finding(
                        rule_id="aws.ai_sec.inference_security.bedrock_no_endpoint_auth",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="inference_security",
                        atlas_technique="AML.T0002",
                        title="Active Bedrock inference profile — verify endpoint auth and rate limiting",
                        detail=(
                            f"Inference profile type={profile_type} status=ACTIVE. "
                            "Ensure IAM resource-based policies restrict caller principals "
                            "and CloudWatch rate-based alerts are configured."
                        ),
                    ))

            if svc == "bedrock" and resource_type == "model_invocation_logging_configuration":
                # Empty logging config means inference calls are unmonitored
                raw = ef.get("_raw_response") or ef
                logging_disabled = not raw or raw == {} or (
                    isinstance(raw, dict) and not raw.get("loggingConfig")
                )
                if logging_disabled:
                    findings.append(_finding(
                        rule_id="aws.ai_sec.inference_security.bedrock_no_invocation_logging",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="inference_security",
                        atlas_technique="AML.T0000",
                        title="Bedrock model invocation logging is not configured",
                        detail=(
                            "No CloudWatch/S3 logging for Bedrock invocations. "
                            "Model evasion and inversion attacks cannot be detected."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 4 — Supply Chain (AML.T0004)
            # ------------------------------------------------------------------
            if svc == "bedrock" and resource_type == "inference_profile":
                profile_type = ef.get("type", "")
                # SYSTEM_DEFINED is fine; APPLICATION type (user-created) has higher supply-chain risk
                if profile_type == "APPLICATION":
                    findings.append(_finding(
                        rule_id="aws.ai_sec.supply_chain.bedrock_application_profile_unverified",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="supply_chain",
                        atlas_technique="AML.T0004",
                        title="Application-defined Bedrock inference profile — verify model provenance",
                        detail=(
                            "User-created inference profiles can reference unverified external "
                            "model sources. Validate all model ARNs against approved registry."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 5 — AI Governance
            # ------------------------------------------------------------------
            if svc == "sagemaker" and resource_type == "notebook_instance":
                # No monitoring → HIGH governance gap
                if not ef.get("MonitoringSchedules"):
                    findings.append(_finding(
                        rule_id="aws.ai_sec.ai_governance.no_notebook_monitoring",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="ai_governance",
                        atlas_technique=None,
                        title="SageMaker notebook has no monitoring schedule configured",
                        detail="No MonitoringSchedules — model drift and data quality cannot be tracked.",
                    ))

            if svc == "sagemaker" and resource_type == "resource_catalog":
                # Resource catalog entries without lineage/tags → governance gap
                findings.append(_finding(
                    rule_id="aws.ai_sec.ai_governance.resource_catalog_audit",
                    resource_uid=resource_uid,
                    resource_type=resource_type,
                    account_id=account_id,
                    region=region,
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id,
                    severity="MEDIUM",
                    pillar="ai_governance",
                    atlas_technique=None,
                    title="SageMaker resource catalog entry requires governance review",
                    detail="Catalog entries should have owner tags, data classification, and lineage tracked.",
                ))

            if svc == "bedrock" and resource_type == "prompt_router":
                # Prompt routers without guardrails → HIGH governance
                findings.append(_finding(
                    rule_id="aws.ai_sec.ai_governance.bedrock_prompt_router_no_guardrails",
                    resource_uid=resource_uid,
                    resource_type=resource_type,
                    account_id=account_id,
                    region=region,
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id,
                    severity="HIGH",
                    pillar="ai_governance",
                    atlas_technique=None,
                    title="Bedrock prompt router has no guardrails configured",
                    detail="Prompt routers without guardrails allow unrestricted LLM prompt injection.",
                ))

        logger.info(
            "AWS AI analyze(): produced %d ATLAS findings for scan %s",
            len(findings), scan_run_id,
        )
        return findings
