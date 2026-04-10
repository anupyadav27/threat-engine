"""
GuardDuty Finding parser — JSON findings exported to S3.

GuardDuty findings are OCSF-like already:
{
  "id": "...",
  "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
  "severity": 8,
  "title": "...",
  "description": "...",
  "resource": {"resourceType": "Instance", ...},
  "service": {"action": {"actionType": "AWS_API_CALL", ...}},
  ...
}
"""

import gzip
import json
import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    (0, 4): "low",
    (4, 7): "medium",
    (7, 10): "high",
}


class GuardDutyParser(BaseParser):
    format_name = "guardduty"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        """Parse GuardDuty JSON findings from S3."""
        try:
            # May be gzipped
            try:
                text = gzip.decompress(raw_bytes).decode("utf-8")
            except (gzip.BadGzipFile, OSError):
                text = raw_bytes.decode("utf-8", errors="replace")

            # Could be JSON lines or JSON array
            findings = []
            text = text.strip()
            if text.startswith("["):
                findings = json.loads(text)
            else:
                for line in text.split("\n"):
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

            for finding in findings:
                if not isinstance(finding, dict):
                    continue

                sev_num = finding.get("severity", 0)
                severity = "medium"
                for (lo, hi), sev in _SEVERITY_MAP.items():
                    if lo <= sev_num < hi:
                        severity = sev
                        break

                service = finding.get("service", {})
                action = service.get("action", {})
                action_type = action.get("actionType", "")
                api_call = action.get("awsApiCallAction", {})
                network = action.get("networkConnectionAction", {})
                remote_ip = (
                    api_call.get("remoteIpDetails", {}).get("ipAddressV4", "")
                    or network.get("remoteIpDetails", {}).get("ipAddressV4", "")
                )

                resource = finding.get("resource", {})
                resource_type = resource.get("resourceType", "")

                record = {
                    "finding_id": finding.get("id", ""),
                    "finding_type": finding.get("type", ""),
                    "title": finding.get("title", ""),
                    "description": finding.get("description", ""),
                    "severity": severity,
                    "severity_num": sev_num,
                    "resource_type": resource_type,
                    "action_type": action_type,
                    "service_name": api_call.get("serviceName", ""),
                    "api_name": api_call.get("api", ""),
                    "remote_ip": remote_ip,
                    "country": api_call.get("remoteIpDetails", {}).get("country", {}).get("countryName", ""),
                    "account_id": finding.get("accountId", ""),
                    "region": finding.get("region", ""),
                    "created_at": finding.get("createdAt", ""),
                    "updated_at": finding.get("updatedAt", ""),
                    "source": "guardduty",
                }

                yield record

        except Exception as exc:
            logger.debug(f"GuardDuty parse error: {exc}")

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "event_id": "finding_id",
            "event_time": "updated_at",
            "operation": "finding_type",
            "actor.ip_address": "remote_ip",
            "resource.type": "resource_type",
            "resource.account_id": "account_id",
        }

    def get_event_category(self) -> str:
        return EventCategory.SECURITY_FINDING
