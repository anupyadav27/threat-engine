"""
Shadow AI Detector.

Cross-references CIEM invocation data with discovery inventory to find
unregistered ML/AI service usage (Shadow AI) and detect anomalous
AI usage patterns.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# CloudTrail operations that indicate AI/ML service usage
AI_OPERATIONS: Dict[str, List[str]] = {
    "sagemaker": [
        "InvokeEndpoint", "InvokeEndpointAsync", "CreateEndpoint",
        "CreateModel", "CreateTrainingJob", "CreateNotebookInstance",
    ],
    "bedrock": [
        "InvokeModel", "InvokeModelWithResponseStream", "Converse",
        "ConverseStream", "ApplyGuardrail", "CreateModelCustomizationJob",
    ],
    "comprehend": [
        "DetectSentiment", "DetectEntities", "DetectKeyPhrases",
        "ClassifyDocument", "DetectPiiEntities",
    ],
    "rekognition": [
        "DetectFaces", "DetectLabels", "RecognizeCelebrities",
        "SearchFacesByImage", "DetectText", "DetectModerationLabels",
    ],
    "textract": [
        "AnalyzeDocument", "DetectDocumentText", "AnalyzeExpense",
    ],
    "transcribe": [
        "StartTranscriptionJob", "StartStreamTranscription",
    ],
    "translate": [
        "TranslateText", "TranslateDocument",
    ],
    "polly": [
        "SynthesizeSpeech",
    ],
    "lex": [
        "RecognizeText", "RecognizeUtterance",
    ],
    "kendra": [
        "Query", "Retrieve",
    ],
    "personalize": [
        "GetRecommendations", "GetPersonalizedRanking",
    ],
    "forecast": [
        "QueryForecast",
    ],
}

# Flattened set of all AI operations for fast lookup
_ALL_AI_OPS: Set[str] = set()
_OP_TO_SERVICE: Dict[str, str] = {}
for _svc, _ops in AI_OPERATIONS.items():
    for _op in _ops:
        _ALL_AI_OPS.add(_op)
        _OP_TO_SERVICE[_op] = _svc

# Threshold constants
_HIGH_ERROR_RATE_PCT = 5.0
_ANOMALOUS_CALLERS_THRESHOLD = 100
_HIGH_VOLUME_SINGLE_PRINCIPAL = 1000


def _finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Deterministic finding ID: sha256(rule_id|resource_uid|account_id|region)[:16]."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class ShadowAIDetector:
    """Detects ML/AI resources being used but not in discovery inventory."""

    def detect_shadow_ai(
        self,
        ciem_invocations: List[Dict[str, Any]],
        discovery_resources: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Find AI service calls with no matching discovered resource.

        1. Build set of known resource UIDs from discovery.
        2. For each CIEM invocation of AI operations, if resource_uid NOT in
           known set, flag as Shadow AI.
        3. Deduplicate by (service, operation, actor_principal).
        4. Score by frequency and recency.

        Args:
            ciem_invocations: CIEM invocation records with event_name,
                resource_uid, actor_principal, timestamp, account_id, region.
            discovery_resources: Discovered resource dicts with resource_uid.

        Returns:
            List of shadow AI finding dicts.
        """
        if not ciem_invocations:
            return []

        # Build known resource UID set
        known_uids: Set[str] = set()
        for r in (discovery_resources or []):
            uid = r.get("resource_uid", "")
            if uid:
                known_uids.add(uid)

        # Group unregistered AI invocations by (service, operation, principal)
        shadow_groups: Dict[tuple, Dict[str, Any]] = {}

        for inv in ciem_invocations:
            event_name = inv.get("event_name") or inv.get("operation", "")
            if event_name not in _ALL_AI_OPS:
                continue

            resource_uid = inv.get("resource_uid", "")
            if resource_uid in known_uids:
                continue

            service = _OP_TO_SERVICE.get(event_name, "unknown")
            principal = inv.get("actor_principal", "")
            account_id = inv.get("account_id", "")
            region = inv.get("region", "")
            timestamp = inv.get("timestamp") or inv.get("event_time", "")

            key = (service, event_name, principal, account_id, region)
            if key not in shadow_groups:
                shadow_groups[key] = {
                    "service": service,
                    "operation": event_name,
                    "actor_principal": principal,
                    "account_id": account_id,
                    "region": region,
                    "resource_uid": resource_uid or f"arn:aws:{service}:{region}:{account_id}:shadow",
                    "call_count": 0,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                }

            group = shadow_groups[key]
            group["call_count"] += 1
            if timestamp and timestamp > group["last_seen"]:
                group["last_seen"] = timestamp
            if timestamp and timestamp < group["first_seen"]:
                group["first_seen"] = timestamp

        # Convert to findings
        findings: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()

        for group in shadow_groups.values():
            resource_uid = group["resource_uid"]
            account_id = group["account_id"]
            region = group["region"]
            service = group["service"]

            findings.append({
                "finding_id": _finding_id("AI-GOV-002", resource_uid, account_id, region),
                "rule_id": "AI-GOV-002",
                "severity": "HIGH",
                "status": "FAIL",
                "category": "ai_governance",
                "title": f"Shadow AI detected \u2014 unregistered {service} usage",
                "detail": (
                    f"Detected {group['call_count']} call(s) to {service}.{group['operation']} "
                    f"by principal '{group['actor_principal']}' with no matching "
                    f"resource in discovery inventory."
                ),
                "remediation": (
                    "Register all ML models in SageMaker Model Registry with "
                    "version tracking and model cards."
                ),
                "resource_uid": resource_uid,
                "ml_service": service,
                "account_id": account_id,
                "region": region,
                "actor_principal": group["actor_principal"],
                "operation": group["operation"],
                "call_count": group["call_count"],
                "first_seen": group["first_seen"],
                "last_seen": group["last_seen"],
                "detected_at": now,
            })

        # Sort by call_count descending (most active shadow AI first)
        findings.sort(key=lambda f: f["call_count"], reverse=True)

        logger.info(
            "Shadow AI detection: %d shadow findings from %d invocations",
            len(findings),
            len(ciem_invocations),
        )
        return findings

    def detect_unusual_ai_usage(
        self,
        ciem_invocations: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Detect anomalous AI usage patterns.

        Checks:
        - AI-GOV-004: High error rate (>5% in 24h)
        - AI-GOV-005: Anomalous input patterns (>100 unique callers in 24h)
        - High-volume single principal (>1000 calls/day)

        Args:
            ciem_invocations: CIEM invocation records with event_name,
                resource_uid, actor_principal, is_error, timestamp.

        Returns:
            List of governance finding dicts.
        """
        if not ciem_invocations:
            return []

        # Filter to AI operations only
        ai_invocations = [
            inv for inv in ciem_invocations
            if (inv.get("event_name") or inv.get("operation", "")) in _ALL_AI_OPS
        ]

        if not ai_invocations:
            return []

        # Group by resource_uid
        by_resource: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for inv in ai_invocations:
            uid = inv.get("resource_uid", "unknown")
            by_resource[uid].append(inv)

        findings: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()

        for resource_uid, invocations in by_resource.items():
            total = len(invocations)
            if total == 0:
                continue

            account_id = invocations[0].get("account_id", "")
            region = invocations[0].get("region", "")
            service = _OP_TO_SERVICE.get(
                invocations[0].get("event_name") or invocations[0].get("operation", ""),
                "unknown",
            )

            # Error rate check
            errors = sum(1 for inv in invocations if inv.get("is_error"))
            error_rate = (errors / total) * 100 if total > 0 else 0.0

            if error_rate > _HIGH_ERROR_RATE_PCT:
                findings.append({
                    "finding_id": _finding_id("AI-GOV-004", resource_uid, account_id, region),
                    "rule_id": "AI-GOV-004",
                    "severity": "MEDIUM",
                    "status": "FAIL",
                    "category": "ai_governance",
                    "title": f"High error rate on {service} endpoint",
                    "detail": (
                        f"Endpoint {resource_uid} shows {error_rate:.1f}% error rate "
                        f"({errors}/{total} calls). Threshold: {_HIGH_ERROR_RATE_PCT}%."
                    ),
                    "remediation": (
                        "Investigate and resolve endpoint errors; consider "
                        "model rollback if error rate persists."
                    ),
                    "resource_uid": resource_uid,
                    "ml_service": service,
                    "account_id": account_id,
                    "region": region,
                    "error_rate_pct": round(error_rate, 2),
                    "total_calls": total,
                    "error_count": errors,
                    "detected_at": now,
                })

            # Unique callers check
            unique_principals: Set[str] = set()
            for inv in invocations:
                p = inv.get("actor_principal", "")
                if p:
                    unique_principals.add(p)

            if len(unique_principals) > _ANOMALOUS_CALLERS_THRESHOLD:
                findings.append({
                    "finding_id": _finding_id("AI-GOV-005", resource_uid, account_id, region),
                    "rule_id": "AI-GOV-005",
                    "severity": "HIGH",
                    "status": "FAIL",
                    "category": "ai_governance",
                    "title": f"Anomalous input patterns on {service} endpoint",
                    "detail": (
                        f"Endpoint {resource_uid} received invocations from "
                        f"{len(unique_principals)} unique principals in 24h. "
                        f"Threshold: {_ANOMALOUS_CALLERS_THRESHOLD}."
                    ),
                    "remediation": (
                        "Investigate input anomalies for adversarial patterns; "
                        "enable input validation and rate limiting."
                    ),
                    "resource_uid": resource_uid,
                    "ml_service": service,
                    "account_id": account_id,
                    "region": region,
                    "unique_callers": len(unique_principals),
                    "total_calls": total,
                    "detected_at": now,
                })

            # High-volume single principal check
            calls_by_principal: Dict[str, int] = defaultdict(int)
            for inv in invocations:
                p = inv.get("actor_principal", "")
                if p:
                    calls_by_principal[p] += 1

            for principal, count in calls_by_principal.items():
                if count > _HIGH_VOLUME_SINGLE_PRINCIPAL:
                    fid = _finding_id(
                        "AI-GOV-005", f"{resource_uid}|{principal}", account_id, region,
                    )
                    findings.append({
                        "finding_id": fid,
                        "rule_id": "AI-GOV-005",
                        "severity": "HIGH",
                        "status": "FAIL",
                        "category": "ai_governance",
                        "title": f"High-volume AI usage by single principal on {service}",
                        "detail": (
                            f"Principal '{principal}' made {count} calls to "
                            f"{resource_uid} in 24h. "
                            f"Threshold: {_HIGH_VOLUME_SINGLE_PRINCIPAL}."
                        ),
                        "remediation": (
                            "Review principal activity for automation abuse or "
                            "credential compromise; enforce rate limiting."
                        ),
                        "resource_uid": resource_uid,
                        "ml_service": service,
                        "account_id": account_id,
                        "region": region,
                        "actor_principal": principal,
                        "call_count": count,
                        "detected_at": now,
                    })

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: severity_order.get(f["severity"], 9))

        logger.info(
            "Unusual AI usage detection: %d findings from %d resources",
            len(findings),
            len(by_resource),
        )
        return findings
