"""
AI Finding Categorizer.

Maps check engine findings to AI security modules and generates
AI-specific findings from cross-engine data (IAM, DataSec, Encryption).

Source of truth: rule_metadata table (check DB).
  Scope column   : ai_security JSONB {applicable: true}
  Module mapping : subcategory → module via _SUBCATEGORY_TO_MODULE below.
  Service list   : service column WHERE ai_security applicable.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── Subcategory → AI module (stable semantic mapping, not per-rule) ───────────
_SUBCATEGORY_TO_MODULE: Dict[str, str] = {
    "encryption_at_rest":        "model_security",
    "storage_encryption":        "model_security",
    "model_security":            "model_security",
    "encryption_in_transit":     "endpoint_security",
    "network_access_control":    "endpoint_security",
    "public_exposure_prevention": "endpoint_security",
    "rate_limiting":             "endpoint_security",
    "intrusion_detection":       "prompt_security",
    "malware_protection":        "prompt_security",
    "data_classification":       "data_pipeline",
    "data_lifecycle_management": "data_pipeline",
    "backup_and_recovery":       "data_pipeline",
    "audit_logging":             "ai_governance",
    "security_monitoring":       "ai_governance",
    "alerting":                  "ai_governance",
    "compliance_monitoring":     "ai_governance",
    "configuration_baseline":    "ai_governance",
    "policy_enforcement":        "ai_governance",
    "change_management":         "ai_governance",
    "authentication":            "access_control",
    "authorization":             "access_control",
    "least_privilege":           "access_control",
    "identity_federation":       "access_control",
    "key_management":            "access_control",
    "credential_storage":        "access_control",
}

# ── DB-loaded tables (lazy, cached via CategoryLoader) ───────────────────────
_rule_module_map: Dict[str, str] = {}
_ai_service_prefixes: Set[str] = set()
_loaded = False


def _ensure_loaded() -> None:
    global _rule_module_map, _ai_service_prefixes, _loaded
    if _loaded:
        return
    _loaded = True
    from engine_common.category_loader import load_rule_domain_map, load_engine_services
    from engine_common.db_connections import get_check_conn
    _rule_module_map = load_rule_domain_map(
        "ai_security", get_check_conn, _SUBCATEGORY_TO_MODULE, "model_security"
    )
    # Derive "<csp>.<service>" prefix set from loaded rule_ids (no extra query needed)
    _ai_service_prefixes = {
        f"{r.split('.')[0]}.{r.split('.')[1]}"
        for r in _rule_module_map
        if len(r.split(".")) >= 2
    }
    logger.info("finding_categorizer: %d rules, %d service prefixes loaded",
                len(_rule_module_map), len(_ai_service_prefixes))


# ── Private helpers ───────────────────────────────────────────────────────────

def _finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _map_check_rule_to_module(rule_id: str) -> Optional[str]:
    _ensure_loaded()
    return _rule_module_map.get(rule_id)


def _is_ai_check_rule(rule_id: str) -> bool:
    _ensure_loaded()
    rule_lower = rule_id.lower()
    return any(rule_lower.startswith(p) for p in _ai_service_prefixes)


# ── ML resource detection (resource identification, not categorisation) ────────

_ML_ARN_PATTERNS = (
    ":sagemaker:", ":bedrock:", ":comprehend:", ":rekognition:",
    ":textract:", ":transcribe:", ":translate:", ":polly:",
    ":lex:", ":kendra:", ":personalize:", ":forecast:",
)
_ML_DATA_PATTERNS = ("sagemaker", "ml-", "training", "model", "dataset")


def _is_ml_resource(resource_uid: str) -> bool:
    uid = resource_uid.lower()
    return any(p in uid for p in _ML_ARN_PATTERNS)


def _is_ml_data_resource(resource_uid: str) -> bool:
    uid = resource_uid.lower()
    if ":s3:" in uid or "s3:::" in uid:
        return any(kw in uid for kw in _ML_DATA_PATTERNS)
    return _is_ml_resource(uid)


def _service_from_uid(resource_uid: str) -> str:
    uid = resource_uid.lower()
    for pattern in _ML_ARN_PATTERNS:
        if pattern in uid:
            return pattern.strip(":")
    return "unknown"


def _extract_service_from_rule(rule_id: str) -> str:
    parts = rule_id.lower().split(".")
    return parts[1] if len(parts) >= 2 else "unknown"


# ── Public class ──────────────────────────────────────────────────────────────

class AIFindingCategorizer:
    """Maps check findings to AI security modules and generates AI-specific findings."""

    def categorize_findings(
        self,
        check_findings: List[Dict[str, Any]],
        _ai_rules: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        seen_ids: set = set()
        findings: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()

        for cf in (check_findings or []):
            rule_id = cf.get("rule_id", "")
            if not _is_ai_check_rule(rule_id):
                continue

            resource_uid = cf.get("resource_uid", "")
            account_id = cf.get("account_id", "")
            region = cf.get("region", "")
            fid = _finding_id(rule_id, resource_uid, account_id, region)
            if fid in seen_ids:
                continue
            seen_ids.add(fid)

            findings.append({
                "finding_id": fid,
                "rule_id": rule_id,
                "severity": (cf.get("severity") or "MEDIUM").upper(),
                "status": (cf.get("status") or "FAIL").upper(),
                "category": _map_check_rule_to_module(rule_id) or "model_security",
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

        logger.info("Categorized %d AI findings from %d check findings",
                    len(findings), len(check_findings or []))
        return findings

    def categorize_cross_engine_findings(
        self,
        iam_findings: List[Dict[str, Any]],
        datasec_findings: List[Dict[str, Any]],
        encryption_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()

        for f in (iam_findings or []):
            resource_uid = f.get("resource_uid", "")
            if not _is_ml_resource(resource_uid):
                continue
            account_id, region = f.get("account_id", ""), f.get("region", "")
            findings.append({
                "finding_id": _finding_id("AI-AC-001-XREF", resource_uid, account_id, region),
                "rule_id": "AI-AC-001",
                "severity": (f.get("severity") or "HIGH").upper(),
                "status": "FAIL",
                "category": "access_control",
                "title": "Over-privileged IAM role on ML resource",
                "detail": f"IAM finding on ML resource {resource_uid}: {f.get('title', f.get('rule_id', ''))}",
                "remediation": "Apply least-privilege IAM policies scoped to required ML actions only.",
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

        for f in (datasec_findings or []):
            resource_uid = f.get("resource_uid", "")
            if not _is_ml_data_resource(resource_uid):
                continue
            account_id, region = f.get("account_id", ""), f.get("region", "")
            findings.append({
                "finding_id": _finding_id("AI-DP-001-XREF", resource_uid, account_id, region),
                "rule_id": "AI-DP-001",
                "severity": (f.get("severity") or "HIGH").upper(),
                "status": "FAIL",
                "category": "data_pipeline",
                "title": "Training data exposure detected",
                "detail": f"Data security finding on ML data resource {resource_uid}: {f.get('title', f.get('rule_id', ''))}",
                "remediation": "Encrypt training data at rest and restrict access via IAM policies.",
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

        for f in (encryption_findings or []):
            resource_uid = f.get("resource_uid", "")
            if not _is_ml_resource(resource_uid):
                continue
            account_id, region = f.get("account_id", ""), f.get("region", "")
            findings.append({
                "finding_id": _finding_id("AI-MOD-001-XREF", resource_uid, account_id, region),
                "rule_id": "AI-MOD-001",
                "severity": (f.get("severity") or "HIGH").upper(),
                "status": "FAIL",
                "category": "model_security",
                "title": "Unencrypted ML artifact detected",
                "detail": f"Encryption finding on ML resource {resource_uid}: {f.get('title', f.get('rule_id', ''))}",
                "remediation": "Enable SSE-KMS encryption on model artifact bucket.",
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

        logger.info("Cross-engine AI findings: %d (IAM=%d, DataSec=%d, Encryption=%d)",
                    len(findings), len(iam_findings or []),
                    len(datasec_findings or []), len(encryption_findings or []))
        return findings
