"""
EKS Audit Log parser — Kubernetes API server audit events from CloudWatch.

CloudWatch delivers events as JSON messages. Each message is a K8s audit event:
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/default/pods",
  "verb": "create",
  "user": {"username": "system:serviceaccount:kube-system:deployment-controller", "groups": [...]},
  "sourceIPs": ["172.31.1.226"],
  "objectRef": {"resource": "pods", "namespace": "default", "name": "my-pod", "apiVersion": "v1"},
  "responseStatus": {"code": 201},
  "requestReceivedTimestamp": "2026-03-27T10:00:00.000000Z",
  "stageTimestamp": "2026-03-27T10:00:00.100000Z"
}
"""

import json
import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)


class EKSAuditParser(BaseParser):
    format_name = "eks_audit"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        """Parse CloudWatch batch (JSON array of {message, timestamp}).

        Each message is a K8s audit event JSON string.
        """
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            batch = json.loads(text)

            for entry in batch:
                msg = entry.get("message", "")
                if not msg:
                    continue
                try:
                    event = json.loads(msg)
                except (json.JSONDecodeError, TypeError):
                    continue

                # Skip non-audit events and noise
                if event.get("kind") != "Event":
                    continue
                verb = event.get("verb", "")
                if verb in ("get", "list", "watch"):
                    continue  # Skip read-only operations

                # Flatten for normalizer
                user = event.get("user", {})
                obj_ref = event.get("objectRef", {})
                resp_status = event.get("responseStatus", {})
                source_ips = event.get("sourceIPs", [])

                record = {
                    "kind": "Event",
                    "verb": verb,
                    "requestURI": event.get("requestURI", ""),
                    "level": event.get("level", ""),
                    "stage": event.get("stage", ""),
                    # User
                    "user_username": user.get("username", ""),
                    "user_groups": user.get("groups", []),
                    "user_uid": user.get("uid", ""),
                    # Source
                    "source_ip": source_ips[0] if source_ips else "",
                    # Object reference
                    "resource": obj_ref.get("resource", ""),
                    "namespace": obj_ref.get("namespace", ""),
                    "name": obj_ref.get("name", ""),
                    "api_group": obj_ref.get("apiGroup", ""),
                    "api_version": obj_ref.get("apiVersion", ""),
                    "subresource": obj_ref.get("subresource", ""),
                    # Response
                    "response_code": resp_status.get("code", 0),
                    "response_reason": resp_status.get("reason", ""),
                    # Timestamps
                    "requestReceivedTimestamp": event.get("requestReceivedTimestamp", ""),
                    "stageTimestamp": event.get("stageTimestamp", ""),
                    # Annotations (e.g., authorization decisions)
                    "annotations": event.get("annotations", {}),
                }

                yield record

        except Exception as exc:
            logger.debug(f"EKS audit parse error: {exc}")

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "event_time": "requestReceivedTimestamp",
            "operation": "verb",
            "actor.principal": "user_username",
            "actor.ip_address": "source_ip",
            "resource.name": "name",
            "resource.type": "resource",
            "outcome": "response_code",
        }

    def get_event_category(self) -> str:
        return EventCategory.API_ACTIVITY
