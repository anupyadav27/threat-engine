"""
AI Inventory Builder.

Classifies discovered resources as ML/AI and builds a unified inventory
with risk metadata by cross-referencing discovery, check, and CIEM data.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Resource type -> ML service mapping
ML_RESOURCE_TYPES: Dict[str, Dict[str, str]] = {
    "sagemaker.endpoint": {"ml_service": "sagemaker", "deployment_type": "endpoint"},
    "sagemaker.model": {"ml_service": "sagemaker", "deployment_type": "model"},
    "sagemaker.notebook_instance": {"ml_service": "sagemaker", "deployment_type": "notebook"},
    "sagemaker.training_job": {"ml_service": "sagemaker", "deployment_type": "training"},
    "sagemaker.processing_job": {"ml_service": "sagemaker", "deployment_type": "processing"},
    "sagemaker.pipeline": {"ml_service": "sagemaker", "deployment_type": "pipeline"},
    "sagemaker.feature_group": {"ml_service": "sagemaker", "deployment_type": "feature_store"},
    "bedrock.custom_model": {"ml_service": "bedrock", "deployment_type": "model"},
    "bedrock.provisioned_model_throughput": {"ml_service": "bedrock", "deployment_type": "endpoint"},
    "bedrock.guardrail": {"ml_service": "bedrock", "deployment_type": "guardrail"},
    "bedrock.agent": {"ml_service": "bedrock", "deployment_type": "agent"},
    "comprehend.endpoint": {"ml_service": "comprehend", "deployment_type": "endpoint"},
    "rekognition.project": {"ml_service": "rekognition", "deployment_type": "model"},
    "textract.adapter": {"ml_service": "textract", "deployment_type": "model"},
    "forecast.predictor": {"ml_service": "forecast", "deployment_type": "model"},
    "personalize.campaign": {"ml_service": "personalize", "deployment_type": "endpoint"},
    "kendra.index": {"ml_service": "kendra", "deployment_type": "index"},
    "translate.terminology": {"ml_service": "translate", "deployment_type": "model"},
    "lex.bot": {"ml_service": "lex", "deployment_type": "bot"},
}

# LLM / generative model types that require guardrail checks
_LLM_TYPES = frozenset({"llm", "generative"})


class AIInventoryBuilder:
    """Classifies discovered resources as ML/AI and builds inventory with risk metadata."""

    def build_inventory(
        self,
        discovery_resources: List[Dict[str, Any]],
        check_findings: List[Dict[str, Any]],
        ciem_patterns: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Build AI inventory entries from discovery + check + CIEM data.

        For each discovered AI resource:
        1. Classify: ml_service, model_type, framework, deployment_type
        2. Extract security posture from emitted_fields / raw_response
        3. Enrich with check findings (PASS/FAIL counts)
        4. Enrich with CIEM usage (invocations_24h, last_invoked)
        5. Compute risk_score (0-100)

        Args:
            discovery_resources: Raw discovery resource dicts.
            check_findings: Check engine findings with rule_id, resource_uid, status.
            ciem_patterns: CIEM invocation patterns with resource_uid, call_count,
                last_invoked.

        Returns:
            List of inventory dicts matching ai_security_inventory schema.
        """
        if not discovery_resources:
            return []

        # Index check findings by resource_uid
        check_by_resource = _index_check_findings(check_findings or [])

        # Index CIEM patterns by resource_uid
        ciem_by_resource = _index_ciem_patterns(ciem_patterns or [])

        inventory: List[Dict[str, Any]] = []

        for resource in discovery_resources:
            resource_type = (resource.get("resource_type") or "").lower()
            resource_uid = resource.get("resource_uid", "")

            if not resource_uid:
                continue

            # Classify resource
            ml_meta = _classify_resource(resource_type, resource_uid)
            if not ml_meta:
                continue

            ml_service = ml_meta["ml_service"]
            deployment_type = ml_meta["deployment_type"]

            # Extract security posture from emitted_fields / raw_response
            emitted = resource.get("emitted_fields") or {}
            if not isinstance(emitted, dict):
                emitted = {}
            raw = resource.get("raw_response") or {}
            if not isinstance(raw, dict):
                raw = {}

            posture = _extract_security_posture(
                emitted, raw, ml_service, deployment_type,
            )

            # Detect model_type and framework
            model_type = _detect_model_type(emitted, raw, ml_service)
            framework = _detect_framework(emitted, raw)

            # Check findings enrichment
            ck = check_by_resource.get(resource_uid, {"pass": 0, "fail": 0})

            # CIEM enrichment
            ciem = ciem_by_resource.get(resource_uid, {})
            invocations_24h = ciem.get("call_count", 0)
            last_invoked = ciem.get("last_invoked")
            error_rate = ciem.get("error_rate_pct", 0.0)

            # Risk score
            is_llm = model_type in _LLM_TYPES
            risk_score = _compute_risk_score(posture, is_llm, ciem)

            resource_name = (
                resource.get("resource_name")
                or resource.get("name")
                or resource_uid.split("/")[-1].split(":")[-1]
            )

            entry: Dict[str, Any] = {
                "resource_uid": resource_uid,
                "resource_name": resource_name,
                "resource_type": resource_type,
                "ml_service": ml_service,
                "model_type": model_type,
                "framework": framework,
                "deployment_type": deployment_type,
                "account_id": resource.get("account_id", ""),
                "region": resource.get("region", ""),
                "provider": resource.get("provider", "aws"),
                "tags": resource.get("tags") or {},
                # Security posture
                "is_public_endpoint": posture.get("is_public_endpoint", False),
                "is_vpc_isolated": posture.get("is_vpc_isolated", False),
                "encryption_at_rest": posture.get("encryption_at_rest", False),
                "encryption_in_transit": posture.get("encryption_in_transit", False),
                "iam_role_arn": posture.get("iam_role_arn", ""),
                "auth_type": posture.get("auth_type", "iam"),
                "has_model_card": posture.get("has_model_card", False),
                "has_monitoring": posture.get("has_monitoring", False),
                "has_data_capture": posture.get("has_data_capture", False),
                "has_guardrails": posture.get("has_guardrails", False),
                "has_content_filter": posture.get("has_content_filter", False),
                "network_isolation": posture.get("network_isolation", False),
                # Training data
                "training_data_encrypted": posture.get("training_data_encrypted", False),
                "training_vpc_isolated": posture.get("training_vpc_isolated", False),
                # Artifact
                "artifact_encrypted": posture.get("artifact_encrypted", False),
                "artifact_versioned": posture.get("artifact_versioned", False),
                # Check findings
                "check_pass_count": ck["pass"],
                "check_fail_count": ck["fail"],
                # Runtime stats
                "invocations_24h": invocations_24h,
                "last_invoked": last_invoked,
                "error_rate_pct": error_rate,
                # Computed
                "risk_score": risk_score,
            }

            inventory.append(entry)

        logger.info(
            "Built AI inventory: %d ML resources across %d services",
            len(inventory),
            len({e["ml_service"] for e in inventory}),
        )
        return inventory


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _classify_resource(
    resource_type: str, resource_uid: str,
) -> Optional[Dict[str, str]]:
    """Match a resource to an ML service via type string or ARN patterns."""
    # Direct match against ML_RESOURCE_TYPES
    for pattern, meta in ML_RESOURCE_TYPES.items():
        if pattern in resource_type:
            return meta

    # ARN-based fallback
    uid_lower = resource_uid.lower()
    for pattern, meta in ML_RESOURCE_TYPES.items():
        service_prefix = pattern.split(".")[0]
        if f":{service_prefix}:" in uid_lower:
            return meta

    return None


def _extract_security_posture(
    emitted: Dict[str, Any],
    raw: Dict[str, Any],
    ml_service: str,
    deployment_type: str,
) -> Dict[str, Any]:
    """Extract security posture fields from emitted_fields / raw_response.

    Args:
        emitted: Discovery emitted_fields dict.
        raw: Discovery raw_response dict.
        ml_service: Classified ML service name.
        deployment_type: Classified deployment type.

    Returns:
        Dict of security posture booleans and strings.
    """
    combined = {**raw, **emitted}  # emitted takes precedence

    posture: Dict[str, Any] = {
        "is_public_endpoint": False,
        "is_vpc_isolated": False,
        "encryption_at_rest": False,
        "encryption_in_transit": False,
        "iam_role_arn": "",
        "auth_type": "iam",
        "has_model_card": False,
        "has_monitoring": False,
        "has_data_capture": False,
        "has_guardrails": False,
        "has_content_filter": False,
        "network_isolation": False,
        "training_data_encrypted": False,
        "training_vpc_isolated": False,
        "artifact_encrypted": False,
        "artifact_versioned": False,
    }

    # VPC isolation: present in many SageMaker resources
    vpc_config = combined.get("VpcConfig") or combined.get("vpc_config")
    subnet_id = combined.get("SubnetId") or combined.get("Subnets")
    if vpc_config or subnet_id:
        posture["is_vpc_isolated"] = True

    # Encryption at rest: KmsKeyId / KmsKeyArn
    kms_key = (
        combined.get("KmsKeyId")
        or combined.get("KmsKeyArn")
        or combined.get("modelKmsKeyId")
        or combined.get("kms_key_id")
    )
    if kms_key:
        posture["encryption_at_rest"] = True

    # Network isolation
    if combined.get("EnableNetworkIsolation") or combined.get("network_isolation"):
        posture["network_isolation"] = True

    # IAM role
    role_arn = combined.get("ExecutionRoleArn") or combined.get("RoleArn") or ""
    posture["iam_role_arn"] = role_arn

    # --- SageMaker endpoint specifics ---
    if ml_service == "sagemaker" and deployment_type == "endpoint":
        posture["encryption_in_transit"] = bool(
            combined.get("AsyncInferenceConfig")
            or combined.get("encryption_in_transit")
        )
        data_capture = combined.get("DataCaptureConfig") or {}
        if isinstance(data_capture, dict) and data_capture.get("EnableCapture"):
            posture["has_data_capture"] = True

    # --- SageMaker notebook specifics ---
    if ml_service == "sagemaker" and deployment_type == "notebook":
        direct_internet = combined.get("DirectInternetAccess", "Enabled")
        posture["is_public_endpoint"] = (direct_internet == "Enabled")
        root_access = combined.get("RootAccess", "Enabled")
        posture["auth_type"] = "root" if root_access == "Enabled" else "iam"
        if combined.get("SubnetId"):
            posture["is_vpc_isolated"] = True

    # --- SageMaker model specifics ---
    if ml_service == "sagemaker" and deployment_type == "model":
        if combined.get("EnableNetworkIsolation"):
            posture["network_isolation"] = True

    # --- SageMaker training specifics ---
    if ml_service == "sagemaker" and deployment_type == "training":
        posture["training_vpc_isolated"] = posture["is_vpc_isolated"]
        posture["training_data_encrypted"] = posture["encryption_at_rest"]

    # --- Bedrock model specifics ---
    if ml_service == "bedrock" and deployment_type == "model":
        if combined.get("modelKmsKeyId"):
            posture["encryption_at_rest"] = True
        customization_type = combined.get("customizationType", "")
        if customization_type:
            posture["artifact_versioned"] = True

    # --- Bedrock guardrail specifics ---
    if ml_service == "bedrock" and deployment_type == "guardrail":
        posture["has_guardrails"] = True
        if combined.get("contentPolicy") or combined.get("contentPolicyConfig"):
            posture["has_content_filter"] = True

    # --- General monitoring ---
    if combined.get("MonitoringScheduleArn") or combined.get("monitoring_schedule"):
        posture["has_monitoring"] = True

    # --- Model card ---
    if combined.get("ModelCardStatus") or combined.get("model_card"):
        posture["has_model_card"] = True

    # --- Artifact encryption / versioning ---
    artifact_bucket = combined.get("OutputDataConfig", {})
    if isinstance(artifact_bucket, dict) and artifact_bucket.get("KmsKeyId"):
        posture["artifact_encrypted"] = True
    if combined.get("ModelPackageGroupName") or combined.get("ModelApprovalStatus"):
        posture["artifact_versioned"] = True

    return posture


def _detect_model_type(
    emitted: Dict[str, Any], raw: Dict[str, Any], ml_service: str,
) -> str:
    """Infer model_type from resource metadata.

    Returns:
        One of: llm, generative, classification, regression, nlp, cv, custom.
    """
    combined = {**raw, **emitted}

    # Bedrock models are typically LLM / generative
    if ml_service == "bedrock":
        return "llm"

    # Check for explicit model type indicators
    model_name = (combined.get("ModelName") or combined.get("model_id") or "").lower()
    image_uri = (combined.get("ImageUri") or combined.get("PrimaryContainer", {}).get("Image", "") or "").lower()

    if any(kw in model_name or kw in image_uri for kw in ("llm", "gpt", "llama", "claude", "falcon")):
        return "llm"
    if any(kw in model_name or kw in image_uri for kw in ("stable-diffusion", "diffusion", "generative")):
        return "generative"
    if any(kw in image_uri for kw in ("xgboost", "linear-learner", "factorization")):
        return "classification"
    if any(kw in image_uri for kw in ("forecasting", "deepar")):
        return "regression"
    if any(kw in image_uri for kw in ("blazingtext", "ntm", "seq2seq", "huggingface-text")):
        return "nlp"
    if any(kw in image_uri for kw in ("image-classification", "object-detection", "semantic-segmentation")):
        return "cv"

    # Service-based defaults
    service_defaults = {
        "comprehend": "nlp",
        "rekognition": "cv",
        "textract": "cv",
        "forecast": "regression",
        "personalize": "classification",
        "translate": "nlp",
        "transcribe": "nlp",
        "polly": "nlp",
        "lex": "nlp",
        "kendra": "nlp",
    }
    return service_defaults.get(ml_service, "custom")


def _detect_framework(emitted: Dict[str, Any], raw: Dict[str, Any]) -> str:
    """Infer ML framework from container image or metadata.

    Returns:
        One of: pytorch, tensorflow, huggingface, xgboost, sklearn, mxnet, custom.
    """
    combined = {**raw, **emitted}
    image_uri = (
        combined.get("ImageUri")
        or (combined.get("PrimaryContainer") or {}).get("Image", "")
        or ""
    ).lower()
    framework_name = (combined.get("Framework") or combined.get("framework") or "").lower()

    candidates = image_uri + " " + framework_name

    if "pytorch" in candidates:
        return "pytorch"
    if "tensorflow" in candidates or "tf-" in candidates:
        return "tensorflow"
    if "huggingface" in candidates:
        return "huggingface"
    if "xgboost" in candidates:
        return "xgboost"
    if "sklearn" in candidates or "scikit" in candidates:
        return "sklearn"
    if "mxnet" in candidates:
        return "mxnet"

    return "custom"


def _compute_risk_score(
    posture: Dict[str, Any], is_llm: bool, ciem: Dict[str, Any],
) -> int:
    """Compute a 0-100 risk score based on security posture gaps.

    Scoring:
        - Public endpoint:        +30
        - No encryption at rest:  +20
        - No VPC isolation:       +15
        - No monitoring:          +10
        - No guardrails (LLM):    +25
        - Overprivileged role:    +15
        - High error rate (>5%):  +10

    Args:
        posture: Security posture dict.
        is_llm: Whether the resource is an LLM/generative model.
        ciem: CIEM usage data for the resource.

    Returns:
        Risk score clamped to 0-100.
    """
    score = 0

    if posture.get("is_public_endpoint"):
        score += 30

    if not posture.get("encryption_at_rest"):
        score += 20

    if not posture.get("is_vpc_isolated"):
        score += 15

    if not posture.get("has_monitoring"):
        score += 10

    if is_llm and not posture.get("has_guardrails"):
        score += 25

    # Overprivileged role heuristic: role name contains "Admin" or "*"
    role = posture.get("iam_role_arn", "")
    if "admin" in role.lower() or "AdministratorAccess" in role:
        score += 15

    # High error rate
    error_rate = ciem.get("error_rate_pct", 0.0)
    if isinstance(error_rate, (int, float)) and error_rate > 5.0:
        score += 10

    return min(score, 100)


def _index_check_findings(
    check_findings: List[Dict[str, Any]],
) -> Dict[str, Dict[str, int]]:
    """Index check findings by resource_uid with PASS/FAIL counts."""
    by_resource: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"pass": 0, "fail": 0}
    )
    for f in check_findings:
        uid = f.get("resource_uid", "")
        if not uid:
            continue
        status = (f.get("status") or "").upper()
        if status == "PASS":
            by_resource[uid]["pass"] += 1
        else:
            by_resource[uid]["fail"] += 1
    return dict(by_resource)


def _index_ciem_patterns(
    ciem_patterns: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Index CIEM invocation patterns by resource_uid."""
    by_resource: Dict[str, Dict[str, Any]] = {}
    for c in ciem_patterns:
        uid = c.get("resource_uid", "")
        if not uid:
            continue
        by_resource[uid] = {
            "call_count": c.get("call_count", 0),
            "last_invoked": c.get("last_invoked"),
            "error_rate_pct": c.get("error_rate_pct", 0.0),
        }
    return by_resource
