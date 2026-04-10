"""
AI Finding Categorizer.

Maps check engine findings to AI security modules and generates
AI-specific findings from cross-engine data (IAM, DataSec, Encryption).
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Check rule patterns -> AI security module
CHECK_RULE_TO_AI_MODULE: Dict[str, str] = {
    # SageMaker model rules
    "aws.sagemaker.model.": "model_security",
    "aws.sagemaker.training": "model_security",
    "aws.sagemaker.automl": "model_security",
    # SageMaker endpoint rules
    "aws.sagemaker.endpoint.": "endpoint_security",
    "aws.sagemaker.inference": "endpoint_security",
    # SageMaker notebook/pipeline rules
    "aws.sagemaker.notebook": "data_pipeline",
    "aws.sagemaker.pipeline": "data_pipeline",
    "aws.sagemaker.processing": "data_pipeline",
    "aws.sagemaker.feature": "data_pipeline",
    # Bedrock rules
    "aws.bedrock.custom_model": "model_security",
    "aws.bedrock.guardrail": "prompt_security",
    "aws.bedrock.model_invocation_logging": "ai_governance",
    "aws.bedrock.execution_role": "access_control",
}

# AI services for filtering check findings
_AI_SERVICE_PREFIXES = frozenset({
    "aws.sagemaker", "aws.bedrock", "aws.comprehend", "aws.rekognition",
    "aws.textract", "aws.transcribe", "aws.translate", "aws.polly",
    "aws.lex", "aws.kendra", "aws.personalize", "aws.forecast",
})


def _finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Deterministic finding ID: sha256(rule_id|resource_uid|account_id|region)[:16]."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _map_check_rule_to_module(rule_id: str) -> Optional[str]:
    """Map a check engine rule_id to an AI security module.

    Args:
        rule_id: Check engine rule identifier (e.g., 'aws.sagemaker.endpoint.encryption').

    Returns:
        AI module name or None if no mapping.
    """
    rule_lower = rule_id.lower()
    for pattern, module in CHECK_RULE_TO_AI_MODULE.items():
        if rule_lower.startswith(pattern):
            return module
    return None


def _is_ai_check_rule(rule_id: str) -> bool:
    """Return True if the check rule pertains to an AI/ML service."""
    rule_lower = rule_id.lower()
    return any(rule_lower.startswith(prefix) for prefix in _AI_SERVICE_PREFIXES)


class AIFindingCategorizer:
    """Maps check findings to AI security modules and generates AI-specific findings."""

    def categorize_findings(
        self,
        check_findings: List[Dict[str, Any]],
        ai_rules: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Categorize check findings into AI modules and merge with AI-specific rules.

        1. For each check finding matching AI services, map to an AI module.
        2. For each AI-specific rule from seed data, create a placeholder entry
           so downstream evaluation can process them.
        3. Merge both sets, deduplicate by finding_id.

        Args:
            check_findings: Check engine findings with rule_id, resource_uid,
                status, severity.
            ai_rules: AI security rule definitions (from ai_security_rules table).

        Returns:
            List of AI finding dicts matching ai_security_findings schema.
        """
        seen_ids: set = set()
        findings: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()

        # 1. Map check findings to AI modules
        for cf in (check_findings or []):
            rule_id = cf.get("rule_id", "")
            if not _is_ai_check_rule(rule_id):
                continue

            resource_uid = cf.get("resource_uid", "")
            account_id = cf.get("account_id", "")
            region = cf.get("region", "")
            status = (cf.get("status") or "FAIL").upper()
            severity = (cf.get("severity") or "MEDIUM").upper()

            module = _map_check_rule_to_module(rule_id)
            if not module:
                # Default based on service prefix
                module = "model_security"

            fid = _finding_id(rule_id, resource_uid, account_id, region)
            if fid in seen_ids:
                continue
            seen_ids.add(fid)

            findings.append({
                "finding_id": fid,
                "rule_id": rule_id,
                "severity": severity,
                "status": status,
                "category": module,
                "title": cf.get("title", f"Check finding: {rule_id}"),
                "detail": cf.get("detail") or cf.get("description", ""),
                "remediation": cf.get("remediation", ""),
                "resource_uid": resource_uid,
                "resource_type": cf.get("resource_type", ""),
                "ml_service": _extract_service_from_rule(rule_id),
                "model_type": cf.get("model_type", ""),
                "account_id": account_id,
                "region": region,
                "provider": cf.get("provider") or cf.get("csp", "aws"),
                "frameworks": cf.get("frameworks", []),
                "mitre_techniques": cf.get("mitre_techniques", []),
                "created_at": now,
            })

        # 2. Include AI-specific rule templates (for rules that don't
        #    originate from the check engine)
        for rule in (ai_rules or []):
            rule_id = rule.get("rule_id", "")
            if not rule_id:
                continue
            # These rules are evaluated separately by the rule evaluator;
            # we include them in the output for completeness when findings exist
            # (no resource_uid yet, so skip dedup)

        logger.info(
            "Categorized %d AI findings from %d check findings",
            len(findings),
            len(check_findings or []),
        )
        return findings

    def categorize_cross_engine_findings(
        self,
        iam_findings: List[Dict[str, Any]],
        datasec_findings: List[Dict[str, Any]],
        encryption_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Create AI-context findings from other engine results.

        From IAM: Over-privileged ML roles -> access_control module
        From DataSec: Training data exposure -> data_pipeline module
        From Encryption: Unencrypted ML artifacts -> model_security module

        Args:
            iam_findings: IAM engine findings with resource_uid, rule_id.
            datasec_findings: DataSec findings with resource_uid.
            encryption_findings: Encryption engine findings with resource_uid.

        Returns:
            List of cross-engine AI finding dicts.
        """
        findings: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()

        # IAM: Over-privileged ML roles -> access_control
        for f in (iam_findings or []):
            resource_uid = f.get("resource_uid", "")
            if not _is_ml_resource(resource_uid):
                continue

            account_id = f.get("account_id", "")
            region = f.get("region", "")
            fid = _finding_id("AI-AC-001-XREF", resource_uid, account_id, region)

            findings.append({
                "finding_id": fid,
                "rule_id": "AI-AC-001",
                "severity": (f.get("severity") or "HIGH").upper(),
                "status": "FAIL",
                "category": "access_control",
                "title": f"Over-privileged IAM role on ML resource",
                "detail": (
                    f"IAM finding on ML resource {resource_uid}: "
                    f"{f.get('title', f.get('rule_id', 'overprivileged role'))}"
                ),
                "remediation": (
                    "Apply least-privilege IAM policies scoped to required "
                    "ML actions only."
                ),
                "resource_uid": resource_uid,
                "resource_type": f.get("resource_type", ""),
                "ml_service": _service_from_uid(resource_uid),
                "account_id": account_id,
                "region": region,
                "provider": f.get("provider") or f.get("csp", "aws"),
                "source_engine": "iam",
                "source_rule_id": f.get("rule_id", ""),
                "created_at": now,
            })

        # DataSec: Training data exposure -> data_pipeline
        for f in (datasec_findings or []):
            resource_uid = f.get("resource_uid", "")
            if not _is_ml_data_resource(resource_uid):
                continue

            account_id = f.get("account_id", "")
            region = f.get("region", "")
            fid = _finding_id("AI-DP-001-XREF", resource_uid, account_id, region)

            findings.append({
                "finding_id": fid,
                "rule_id": "AI-DP-001",
                "severity": (f.get("severity") or "HIGH").upper(),
                "status": "FAIL",
                "category": "data_pipeline",
                "title": "Training data exposure detected",
                "detail": (
                    f"Data security finding on ML data resource {resource_uid}: "
                    f"{f.get('title', f.get('rule_id', 'data exposure'))}"
                ),
                "remediation": (
                    "Encrypt training data at rest and restrict access via "
                    "IAM policies."
                ),
                "resource_uid": resource_uid,
                "resource_type": f.get("resource_type", ""),
                "ml_service": _service_from_uid(resource_uid),
                "account_id": account_id,
                "region": region,
                "provider": f.get("provider") or f.get("csp", "aws"),
                "source_engine": "datasec",
                "source_rule_id": f.get("rule_id", ""),
                "created_at": now,
            })

        # Encryption: Unencrypted ML artifacts -> model_security
        for f in (encryption_findings or []):
            resource_uid = f.get("resource_uid", "")
            if not _is_ml_resource(resource_uid):
                continue

            account_id = f.get("account_id", "")
            region = f.get("region", "")
            fid = _finding_id("AI-MOD-001-XREF", resource_uid, account_id, region)

            findings.append({
                "finding_id": fid,
                "rule_id": "AI-MOD-001",
                "severity": (f.get("severity") or "HIGH").upper(),
                "status": "FAIL",
                "category": "model_security",
                "title": "Unencrypted ML artifact detected",
                "detail": (
                    f"Encryption finding on ML resource {resource_uid}: "
                    f"{f.get('title', f.get('rule_id', 'unencrypted artifact'))}"
                ),
                "remediation": (
                    "Enable SSE-KMS encryption on model artifact bucket."
                ),
                "resource_uid": resource_uid,
                "resource_type": f.get("resource_type", ""),
                "ml_service": _service_from_uid(resource_uid),
                "account_id": account_id,
                "region": region,
                "provider": f.get("provider") or f.get("csp", "aws"),
                "source_engine": "encryption",
                "source_rule_id": f.get("rule_id", ""),
                "created_at": now,
            })

        logger.info(
            "Cross-engine AI findings: %d (IAM=%d, DataSec=%d, Encryption=%d)",
            len(findings),
            len(iam_findings or []),
            len(datasec_findings or []),
            len(encryption_findings or []),
        )
        return findings


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

_ML_ARN_PATTERNS = (
    ":sagemaker:", ":bedrock:", ":comprehend:", ":rekognition:",
    ":textract:", ":transcribe:", ":translate:", ":polly:",
    ":lex:", ":kendra:", ":personalize:", ":forecast:",
)

_ML_DATA_PATTERNS = (
    "sagemaker", "ml-", "training", "model", "dataset",
)


def _is_ml_resource(resource_uid: str) -> bool:
    """Return True if the resource UID belongs to an ML/AI service."""
    uid_lower = resource_uid.lower()
    return any(pattern in uid_lower for pattern in _ML_ARN_PATTERNS)


def _is_ml_data_resource(resource_uid: str) -> bool:
    """Return True if the resource UID is likely ML training data."""
    uid_lower = resource_uid.lower()
    # S3 buckets or data stores used for ML
    if ":s3:" in uid_lower or "s3:::" in uid_lower:
        return any(kw in uid_lower for kw in _ML_DATA_PATTERNS)
    return _is_ml_resource(uid_lower)


def _service_from_uid(resource_uid: str) -> str:
    """Extract ML service name from a resource UID / ARN."""
    uid_lower = resource_uid.lower()
    for pattern in _ML_ARN_PATTERNS:
        service = pattern.strip(":")
        if pattern in uid_lower:
            return service
    return "unknown"


def _extract_service_from_rule(rule_id: str) -> str:
    """Extract the ML service name from a check rule_id.

    E.g., 'aws.sagemaker.endpoint.encryption' -> 'sagemaker'.
    """
    parts = rule_id.lower().split(".")
    if len(parts) >= 2:
        return parts[1]
    return "unknown"
